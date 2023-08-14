package freeipa

import (
	"fmt"
	"net/http"
)

// Standard FreeIPA error codes.
const (
	PublicErrorCode                           = 900
	VersionErrorCode                          = 901
	UnknownErrorCode                          = 902
	InternalErrorCode                         = 903
	ServerInternalErrorCode                   = 904
	CommandErrorCode                          = 905
	ServerCommandErrorCode                    = 906
	NetworkErrorCode                          = 907
	ServerNetworkErrorCode                    = 908
	JSONErrorCode                             = 909
	XMLRPCMarshallErrorCode                   = 910
	RefererErrorCode                          = 911
	EnvironmentErrorCode                      = 912
	SystemEncodingErrorCode                   = 913
	AuthenticationErrorCode                   = 1000
	KerberosErrorCode                         = 1100
	CCacheErrorCode                           = 1101
	ServiceErrorCode                          = 1102
	NoCCacheErrorCode                         = 1103
	TicketExpiredCode                         = 1104
	BadCCachePermsCode                        = 1105
	BadCCacheFormatCode                       = 1106
	CannotResolveKDCCode                      = 1107
	SessionErrorCode                          = 1200
	InvalidSessionPasswordCode                = 1201
	PasswordExpiredCode                       = 1202
	KrbPrincipalExpiredCode                   = 1203
	UserLockedCode                            = 1204
	AuthorizationErrorCode                    = 2000
	ACIErrorCode                              = 2100
	InvocationErrorCode                       = 3000
	EncodingErrorCode                         = 3001
	BinaryEncodingErrorCode                   = 3002
	ZeroArgumentErrorCode                     = 3003
	MaxArgumentErrorCode                      = 3004
	OptionErrorCode                           = 3005
	OverlapErrorCode                          = 3006
	RequirementErrorCode                      = 3007
	ConversionErrorCode                       = 3008
	ValidationErrorCode                       = 3009
	NoSuchNamespaceErrorCode                  = 3010
	PasswordMismatchCode                      = 3011
	NotImplementedErrorCode                   = 3012
	NotConfiguredErrorCode                    = 3013
	PromptFailedCode                          = 3014
	DeprecationErrorCode                      = 3015
	NotAForestRootErrorCode                   = 3016
	ExecutionErrorCode                        = 4000
	NotFoundCode                              = 4001
	DuplicateEntryCode                        = 4002
	HostServiceCode                           = 4003
	MalformedServicePrincipalCode             = 4004
	RealmMismatchCode                         = 4005
	RequiresRootCode                          = 4006
	AlreadyPosixGroupCode                     = 4007
	MalformedUserPrincipalCode                = 4008
	AlreadyActiveCode                         = 4009
	AlreadyInactiveCode                       = 4010
	HasNSAccountLockCode                      = 4011
	NotGroupMemberCode                        = 4012
	RecursiveGroupCode                        = 4013
	AlreadyGroupMemberCode                    = 4014
	Base64DecodeErrorCode                     = 4015
	RemoteRetrieveErrorCode                   = 4016
	SameGroupErrorCode                        = 4017
	DefaultGroupErrorCode                     = 4018
	DNSNotARecordErrorCode                    = 4019
	ManagedGroupErrorCode                     = 4020
	ManagedPolicyErrorCode                    = 4021
	FileErrorCode                             = 4022
	NoCertificateErrorCode                    = 4023
	ManagedGroupExistsErrorCode               = 4024
	ReverseMemberErrorCode                    = 4025
	AttrValueNotFoundCode                     = 4026
	SingleMatchExpectedCode                   = 4027
	AlreadyExternalGroupCode                  = 4028
	ExternalGroupViolationCode                = 4029
	PosixGroupViolationCode                   = 4030
	EmptyResultCode                           = 4031
	InvalidDomainLevelErrorCode               = 4032
	ServerRemovalErrorCode                    = 4033
	OperationNotSupportedForPrincipalTypeCode = 4034
	HTTPRequestErrorCode                      = 4035
	RedundantMappingRuleCode                  = 4036
	CSRTemplateErrorCode                      = 4037
	AlreadyContainsValueErrorCode             = 4038
	BuiltinErrorCode                          = 4100
	HelpErrorCode                             = 4101
	LDAPErrorCode                             = 4200
	MidairCollisionCode                       = 4201
	EmptyModlistCode                          = 4202
	DatabaseErrorCode                         = 4203
	LimitsExceededCode                        = 4204
	ObjectclassViolationCode                  = 4205
	NotAllowedOnRDNCode                       = 4206
	OnlyOneValueAllowedCode                   = 4207
	InvalidSyntaxCode                         = 4208
	BadSearchFilterCode                       = 4209
	NotAllowedOnNonLeafCode                   = 4210
	DatabaseTimeoutCode                       = 4211
	DNSDataMismatchCode                       = 4212
	TaskTimeoutCode                           = 4213
	TimeLimitExceededCode                     = 4214
	SizeLimitExceededCode                     = 4215
	AdminLimitExceededCode                    = 4216
	CertificateErrorCode                      = 4300
	CertificateOperationErrorCode             = 4301
	CertificateFormatErrorCode                = 4302
	MutuallyExclusiveErrorCode                = 4303
	NonFatalErrorCode                         = 4304
	AlreadyRegisteredErrorCode                = 4305
	NotRegisteredErrorCode                    = 4306
	DependentEntryCode                        = 4307
	LastMemberErrorCode                       = 4308
	ProtectedEntryErrorCode                   = 4309
	CertificateInvalidErrorCode               = 4310
	SchemaUpToDateCode                        = 4311
	DNSErrorCode                              = 4400
	DNSResolverErrorCode                      = 4401
	TrustErrorCode                            = 4500
	TrustTopologyConflictErrorCode            = 4501
	GenericErrorCode                          = 5000
)

// Authentication rejection reasons.
const (
	passwordExpiredUnauthorizedReason        = "password-expired"
	invalidSessionPasswordUnauthorizedReason = "invalid-password"
	krbPrincipalExpiredUnauthorizedReason    = "krbprincipal-expired"
	userLockedUnauthorizedReason             = "user-locked"
	rejectionReasonHTTPHeader                = "X-Ipa-Rejection-Reason"
)

// Add information from the rejection reason header to unauthorized error.
func unauthorizedHTTPError(resp *http.Response) error {
	var errorCode int
	rejectionReason := resp.Header.Get(rejectionReasonHTTPHeader)

	switch rejectionReason {
	case passwordExpiredUnauthorizedReason:
		errorCode = PasswordExpiredCode
	case invalidSessionPasswordUnauthorizedReason:
		errorCode = InvalidSessionPasswordCode
	case krbPrincipalExpiredUnauthorizedReason:
		errorCode = KrbPrincipalExpiredCode
	case userLockedUnauthorizedReason:
		errorCode = UserLockedCode

	default:
		errorCode = GenericErrorCode
	}
	return fmt.Errorf("unauthorized response <%s> (%d)", rejectionReason, errorCode)
}
