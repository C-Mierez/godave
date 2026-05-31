package golibdave

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/disgoorg/godave"
	"github.com/disgoorg/godave/libdave"
)

const (
	initTransitionId         = 0
	disabledProtocolVersion  = 0
	mlsNewGroupExpectedEpoch = 1
)

var (
	_ godave.SessionCreateFunc = NewSession
	_ godave.Session           = (*session)(nil)
)

// NewSession returns a new DAVE session using libdave.
func NewSession(logger *slog.Logger, selfUserID godave.UserID, callbacks godave.Callbacks) godave.Session {
	encryptor := libdave.NewEncryptor()
	// Start in Passthrough by default
	encryptor.SetPassthroughMode(true)

	return &session{
		selfUserID: selfUserID,
		callbacks:  callbacks,
		logger:     logger,
		// Context and authSessionID are only used with persistent key storage and can be ignored most of the time
		session:             libdave.NewSession("", ""),
		encryptor:           encryptor,
		decryptors:          make(map[godave.UserID]*libdave.Decryptor),
		preparedTransitions: make(map[uint16]uint16),
	}
}

type session struct {
	selfUserID                    godave.UserID
	channelID                     godave.ChannelID
	logger                        *slog.Logger
	callbacks                     godave.Callbacks
	session                       *libdave.Session
	encryptor                     *libdave.Encryptor
	decryptors                    map[godave.UserID]*libdave.Decryptor
	preparedTransitions           map[uint16]uint16
	lastPreparedTransitionVersion uint16
}

func (s *session) MaxSupportedProtocolVersion() int {
	return int(libdave.MaxSupportedProtocolVersion())
}

func (s *session) SetChannelID(channelID godave.ChannelID) {
	s.channelID = channelID
}

func (s *session) AssignSsrcToCodec(ssrc uint32, codec godave.Codec) {
	s.encryptor.AssignSsrcToCodec(ssrc, libdave.Codec(codec))
}

func (s *session) MaxEncryptedFrameSize(frameSize int) int {
	return s.encryptor.GetMaxCiphertextByteSize(libdave.MediaTypeAudio, frameSize)
}

func (s *session) Encrypt(ssrc uint32, frame []byte, encryptedFrame []byte) (int, error) {
	return s.encryptor.Encrypt(libdave.MediaTypeAudio, ssrc, frame, encryptedFrame)
}

func (s *session) MaxDecryptedFrameSize(userID godave.UserID, frameSize int) int {
	if decryptor, ok := s.decryptors[userID]; ok {
		return decryptor.GetMaxPlaintextByteSize(libdave.MediaTypeAudio, frameSize)
	}

	// assume passthrough
	return frameSize
}

func (s *session) Decrypt(userID godave.UserID, frame []byte, decryptedFrame []byte) (int, error) {
	s.logger.Debug("Decrypt called",
		slog.String("userID", string(userID)),
		slog.Bool("userID_empty", userID == ""),
		slog.Int("frame_len", len(frame)),
		slog.Int("decryptedFrame_cap", cap(decryptedFrame)),
		slog.Int("num_decryptors", len(s.decryptors)),
	)
	if decryptor, ok := s.decryptors[userID]; ok {
		// Log decryptor stats BEFORE decryption attempt
		statsBefore := decryptor.GetStats(libdave.MediaTypeAudio)
		s.logger.Debug("Decrypt: decryptor stats before",
			slog.String("userID", string(userID)),
			slog.Uint64("successCount", statsBefore.DecryptSuccessCount),
			slog.Uint64("failureCount", statsBefore.DecryptFailureCount),
			slog.Uint64("missingKeyCount", statsBefore.DecryptMissingKeyCount),
			slog.Uint64("invalidNonceCount", statsBefore.DecryptInvalidNonceCount),
		)

		n, err := decryptor.Decrypt(libdave.MediaTypeAudio, frame, decryptedFrame)

		// Log decryptor stats AFTER decryption attempt
		statsAfter := decryptor.GetStats(libdave.MediaTypeAudio)
		s.logger.Debug("Decrypt: decryptor stats after",
			slog.String("userID", string(userID)),
			slog.Uint64("successCount", statsAfter.DecryptSuccessCount),
			slog.Uint64("failureCount", statsAfter.DecryptFailureCount),
			slog.Uint64("missingKeyCount", statsAfter.DecryptMissingKeyCount),
			slog.Uint64("invalidNonceCount", statsAfter.DecryptInvalidNonceCount),
			slog.Any("err", err),
		)

		if err != nil {
			// Key ratchet not yet set up — fall back to passthrough
			if errors.Is(err, libdave.ErrMissingKeyRatchet) {
				s.logger.Warn("Decrypt: ErrMissingKeyRatchet for known user, falling back to passthrough",
					slog.String("userID", string(userID)),
					slog.Int("frame_len", len(frame)),
				)
				return copy(frame, decryptedFrame), nil
			}
			// Log what specific error type it is
			s.logger.Error("Decrypt: error for known user",
				slog.String("userID", string(userID)),
				slog.Any("err", err),
				slog.Bool("isErrMissingKeyRatchet", errors.Is(err, libdave.ErrMissingKeyRatchet)),
				slog.Bool("isErrInvalidNonce", errors.Is(err, libdave.ErrInvalidNonce)),
				slog.Bool("isErrMissingCryptor", errors.Is(err, libdave.ErrMissingCryptor)),
			)
			return 0, err
		}
		return n, nil
	}
	s.logger.Debug("Decrypt: unknown userID, falling back to passthrough",
		slog.String("userID", string(userID)),
	)
	return copy(frame, decryptedFrame), nil
}

func (s *session) AddUser(userID godave.UserID) {
	s.logger.Debug("AddUser called",
		slog.String("userID", string(userID)),
		slog.Any("lastPreparedTransitionVersion", s.lastPreparedTransitionVersion),
		slog.Int("num_prepared_transitions", len(s.preparedTransitions)),
	)
	s.decryptors[userID] = libdave.NewDecryptor()
	s.setupKeyRatchetForUser(userID, s.lastPreparedTransitionVersion)
}

func (s *session) RemoveUser(userID godave.UserID) {
	delete(s.decryptors, userID)
}

func (s *session) OnSelectProtocolAck(protocolVersion uint16) {
	s.protocolInit(protocolVersion)
}

func (s *session) OnDavePrepareTransition(transitionID uint16, protocolVersion uint16) {
	s.prepareTransition(transitionID, protocolVersion)

	if transitionID != initTransitionId {
		s.sendReadyForTransition(transitionID)
	}
}

func (s *session) OnDaveExecuteTransition(transitionID uint16) {
	s.executeTransition(transitionID)
}

func (s *session) OnDavePrepareEpoch(epoch int, protocolVersion uint16) {
	s.prepareEpoch(epoch, protocolVersion)

	if epoch == mlsNewGroupExpectedEpoch {
		s.sendMLSKeyPackage()
	}
}

func (s *session) OnDaveMLSExternalSenderPackage(externalSenderPackage []byte) {
	s.session.SetExternalSender(externalSenderPackage)
}

func (s *session) OnDaveMLSProposals(proposals []byte) {
	commitWelcome := s.session.ProcessProposals(proposals, s.recognizedUserIDs())

	if commitWelcome != nil {
		s.sendMLSCommitWelcome(commitWelcome)
	}
}

func (s *session) OnDaveMLSPrepareCommitTransition(transitionID uint16, commitMessage []byte) {
	res := s.session.ProcessCommit(commitMessage)

	if res.IsIgnored() {
		return
	}

	if res.IsFailed() {
		s.sendInvalidCommitWelcome(transitionID)
		s.protocolInit(s.session.GetProtocolVersion())
		return
	}

	s.prepareTransition(transitionID, s.session.GetProtocolVersion())
	if transitionID != initTransitionId {
		s.sendReadyForTransition(transitionID)
	}
}

func (s *session) OnDaveMLSWelcome(transitionID uint16, welcomeMessage []byte) {
	s.logger.Debug("OnDaveMLSWelcome called",
		slog.Any("transitionID", transitionID),
		slog.Int("welcomeMessage_len", len(welcomeMessage)),
		slog.Int("num_recognized_users", len(s.recognizedUserIDs())),
	)
	res := s.session.ProcessWelcome(welcomeMessage, s.recognizedUserIDs())

	if res == nil {
		s.logger.Warn("OnDaveMLSWelcome: ProcessWelcome returned nil, sending invalid commit")
		s.sendInvalidCommitWelcome(transitionID)
		s.sendMLSKeyPackage()
		return
	}

	s.logger.Info("OnDaveMLSWelcome: ProcessWelcome succeeded, calling prepareTransition",
		slog.Any("transitionID", transitionID),
		slog.Any("protocolVersion", s.session.GetProtocolVersion()),
	)
	s.prepareTransition(transitionID, s.session.GetProtocolVersion())
	if transitionID != initTransitionId {
		s.sendReadyForTransition(transitionID)
	}
}

func (s *session) recognizedUserIDs() []string {
	userIDs := make([]string, 0, len(s.decryptors)+1)

	userIDs = append(userIDs, string(s.selfUserID))

	for userID := range s.decryptors {
		userIDs = append(userIDs, string(userID))
	}

	return userIDs
}

func (s *session) protocolInit(protocolVersion uint16) {
	if protocolVersion > disabledProtocolVersion {
		s.prepareEpoch(mlsNewGroupExpectedEpoch, protocolVersion)
		s.sendMLSKeyPackage()
	} else {
		s.prepareTransition(initTransitionId, protocolVersion)
		s.executeTransition(initTransitionId)
	}
}

func (s *session) prepareEpoch(epoch int, protocolVersion uint16) {
	if epoch != mlsNewGroupExpectedEpoch {
		return
	}

	s.session.Init(protocolVersion, uint64(s.channelID), string(s.selfUserID))
}

func (s *session) executeTransition(transitionID uint16) {
	protocolVersion, ok := s.preparedTransitions[transitionID]
	s.logger.Debug("executeTransition called",
		slog.Any("transitionID", transitionID),
		slog.Bool("transition_prepared", ok),
		slog.Any("protocolVersion", protocolVersion),
		slog.String("selfUserID", string(s.selfUserID)),
		slog.Int("num_decryptors", len(s.decryptors)),
	)
	if !ok {
		s.logger.Warn("executeTransition: transition NOT prepared, returning early (NO KEY RATCHET SET)",
			slog.Any("transitionID", transitionID),
		)
		return
	}

	delete(s.preparedTransitions, transitionID)

	if protocolVersion == disabledProtocolVersion {
		s.session.Reset()
		s.logger.Debug("executeTransition: disabled protocol, reset session")
	}

	s.setupKeyRatchetForUser(s.selfUserID, protocolVersion)
	s.logger.Info("executeTransition complete: bot key ratchet set",
		slog.Any("transitionID", transitionID),
		slog.Any("protocolVersion", protocolVersion),
	)
}

func (s *session) prepareTransition(transitionID uint16, protocolVersion uint16) {
	s.logger.Debug("prepareTransition called",
		slog.Any("transitionID", transitionID),
		slog.Any("protocolVersion", protocolVersion),
		slog.Int("num_decryptors", len(s.decryptors)),
		slog.Bool("is_init_transition", transitionID == initTransitionId),
	)
	for userID := range s.decryptors {
		s.setupKeyRatchetForUser(userID, protocolVersion)
	}

	if transitionID == initTransitionId {
		s.setupKeyRatchetForUser(s.selfUserID, protocolVersion)
	} else {
		s.preparedTransitions[transitionID] = protocolVersion
		s.logger.Info("prepareTransition: stored non-init transition for later execute",
			slog.Any("transitionID", transitionID),
			slog.Any("protocolVersion", protocolVersion),
		)
	}

	s.lastPreparedTransitionVersion = protocolVersion
}

func (s *session) setupKeyRatchetForUser(userID godave.UserID, protocolVersion uint16) {
	disabled := protocolVersion == disabledProtocolVersion
	isSelf := userID == s.selfUserID

	s.logger.Debug("setupKeyRatchetForUser called",
		slog.String("userID", string(userID)),
		slog.Bool("is_self", isSelf),
		slog.Bool("disabled", disabled),
		slog.Any("protocolVersion", protocolVersion),
	)

	if userID == s.selfUserID {
		s.encryptor.SetPassthroughMode(disabled)
		if !disabled {
			kr := s.session.GetKeyRatchet(string(userID))
			s.logger.Info("setupKeyRatchetForUser: bot encryptor key ratchet SET",
				slog.String("userID", string(userID)),
				slog.Any("keyRatchet_ptr", fmt.Sprintf("%p", kr)),
			)
			s.encryptor.SetKeyRatchet(kr)
		}
		return
	}

	decryptor := s.decryptors[userID]
	decryptor.TransitionToPassthroughMode(disabled)
	if !disabled {
		kr := s.session.GetKeyRatchet(string(userID))
		s.logger.Info("setupKeyRatchetForUser: user decryptor key ratchet SET",
			slog.String("userID", string(userID)),
			slog.Any("keyRatchet_ptr", fmt.Sprintf("%p", kr)),
		)
		decryptor.TransitionToKeyRatchet(kr)
	}
}

func (s *session) sendMLSKeyPackage() {
	if err := s.callbacks.SendMLSKeyPackage(s.session.GetMarshalledKeyPackage()); err != nil {
		s.logger.Error("failed to send MLS key package", slog.Any("err", err))
	}
}

func (s *session) sendMLSCommitWelcome(message []byte) {
	if err := s.callbacks.SendMLSCommitWelcome(message); err != nil {
		s.logger.Error("failed to send MLS commit welcome", slog.Any("err", err))
	}
}

func (s *session) sendReadyForTransition(transitionID uint16) {
	if err := s.callbacks.SendReadyForTransition(transitionID); err != nil {
		s.logger.Error("failed to send ready for transition", slog.Any("err", err))
	}
}

func (s *session) sendInvalidCommitWelcome(transitionID uint16) {
	if err := s.callbacks.SendInvalidCommitWelcome(transitionID); err != nil {
		s.logger.Error("failed to send invalid commit welcome", slog.Any("err", err))
	}
}
