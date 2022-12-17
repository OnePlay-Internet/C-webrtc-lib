/**
 * Main public include file
 */
#ifndef __KINESIS_VIDEO_COMMON_INCLUDE__
#define __KINESIS_VIDEO_COMMON_INCLUDE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <CommonDefs.h>
#include <Video.h>

////////////////////////////////////////////////////
// Public headers
////////////////////////////////////////////////////
#ifndef JSMN_HEADER
#define JSMN_HEADER
#endif

////////////////////////////////////////////////////
/// Common producer base return codes
////////////////////////////////////////////////////

/*! \addtogroup CommonProducerBaseStatusCodes
 *  @{
 */

/**
 * This section is done for backward compat. We shouldn't add to it. New status should be added to common base section
 */
#define STATUS_COMMON_PRODUCER_BASE                         0x15000000
#define STATUS_INVALID_AWS_CREDENTIALS_VERSION              STATUS_COMMON_PRODUCER_BASE + 0x00000008
#define STATUS_MAX_REQUEST_HEADER_COUNT                     STATUS_COMMON_PRODUCER_BASE + 0x00000009
#define STATUS_MAX_REQUEST_HEADER_NAME_LEN                  STATUS_COMMON_PRODUCER_BASE + 0x0000000a
#define STATUS_MAX_REQUEST_HEADER_VALUE_LEN                 STATUS_COMMON_PRODUCER_BASE + 0x0000000b
#define STATUS_INVALID_API_CALL_RETURN_JSON                 STATUS_COMMON_PRODUCER_BASE + 0x0000000c
#define STATUS_CURL_INIT_FAILED                             STATUS_COMMON_PRODUCER_BASE + 0x0000000d
#define STATUS_CURL_LIBRARY_INIT_FAILED                     STATUS_COMMON_PRODUCER_BASE + 0x0000000e
#define STATUS_HMAC_GENERATION_ERROR                        STATUS_COMMON_PRODUCER_BASE + 0x00000010
#define STATUS_IOT_FAILED                                   STATUS_COMMON_PRODUCER_BASE + 0x00000011
#define STATUS_MAX_ROLE_ALIAS_LEN_EXCEEDED                  STATUS_COMMON_PRODUCER_BASE + 0x00000012
#define STATUS_INVALID_USER_AGENT_LENGTH                    STATUS_COMMON_PRODUCER_BASE + 0x00000015
#define STATUS_IOT_EXPIRATION_OCCURS_IN_PAST                STATUS_COMMON_PRODUCER_BASE + 0x00000017
#define STATUS_IOT_EXPIRATION_PARSING_FAILED                STATUS_COMMON_PRODUCER_BASE + 0x00000018
#define STATUS_MAX_IOT_THING_NAME_LENGTH                    STATUS_COMMON_PRODUCER_BASE + 0x0000001e
#define STATUS_IOT_CREATE_LWS_CONTEXT_FAILED                STATUS_COMMON_PRODUCER_BASE + 0x0000001f
#define STATUS_INVALID_CA_CERT_PATH                         STATUS_COMMON_PRODUCER_BASE + 0x00000020
#define STATUS_FILE_CREDENTIAL_PROVIDER_OPEN_FILE_FAILED    STATUS_COMMON_PRODUCER_BASE + 0x00000022
#define STATUS_FILE_CREDENTIAL_PROVIDER_INVALID_FILE_LENGTH STATUS_COMMON_PRODUCER_BASE + 0x00000023
#define STATUS_FILE_CREDENTIAL_PROVIDER_INVALID_FILE_FORMAT STATUS_COMMON_PRODUCER_BASE + 0x00000024
#define STATUS_CURL_PERFORM_FAILED                          STATUS_COMMON_PRODUCER_BASE + 0x00000025
#define STATUS_IOT_INVALID_RESPONSE_LENGTH                  STATUS_COMMON_PRODUCER_BASE + 0x00000026
#define STATUS_IOT_NULL_AWS_CREDS                           STATUS_COMMON_PRODUCER_BASE + 0x00000027
#define STATUS_IOT_INVALID_URI_LEN                          STATUS_COMMON_PRODUCER_BASE + 0x00000028
/*!@} */

/**
 * Macro for checking whether the status code should be retried by the continuous retry logic
 */
#define IS_RETRIABLE_COMMON_LIB_ERROR(error)                                                                                                         \
    ((error) == STATUS_INVALID_API_CALL_RETURN_JSON || (error) == STATUS_CURL_INIT_FAILED || (error) == STATUS_CURL_LIBRARY_INIT_FAILED ||           \
     (error) == STATUS_HMAC_GENERATION_ERROR || (error) == STATUS_CURL_PERFORM_FAILED || (error) == STATUS_IOT_INVALID_RESPONSE_LENGTH ||            \
     (error) == STATUS_IOT_NULL_AWS_CREDS || (error) == STATUS_IOT_INVALID_URI_LEN || (error) == STATUS_IOT_EXPIRATION_OCCURS_IN_PAST ||                   \
     (error) == STATUS_IOT_EXPIRATION_PARSING_FAILED || (error) == STATUS_IOT_CREATE_LWS_CONTEXT_FAILED ||                                           \
     (error) == STATUS_FILE_CREDENTIAL_PROVIDER_OPEN_FILE_FAILED || (error) == STATUS_FILE_CREDENTIAL_PROVIDER_INVALID_FILE_LENGTH ||                \
     (error) == STATUS_FILE_CREDENTIAL_PROVIDER_INVALID_FILE_FORMAT)

////////////////////////////////////////////////////
/// New common base status code.
/// All common library status codes defined
/// should continue from the STATUS_COMMON_BASE
////////////////////////////////////////////////////

/*! \addtogroup NewCommonBaseStatusCode
 *  @{
 */

/**
 * Continue errors from the new common base
 */
#define STATUS_COMMON_BASE 0x16000000
/*!@} */

/////////////////////////////////////////////////////
/// Lengths of different character arrays
/////////////////////////////////////////////////////

/*! \addtogroup NameLengths
 * Lengths of some string members of different structures
 *  @{
 */

/**
 * Maximum allowed region name length
 */
#define MAX_REGION_NAME_LEN 128

/**
 * Maximum allowed user agent string length
 */
#define MAX_USER_AGENT_LEN 256

/**
 * Maximum allowed custom user agent string length
 */
#define MAX_CUSTOM_USER_AGENT_LEN 128

/**
 * Maximum allowed custom user agent name postfix string length
 */
#define MAX_CUSTOM_USER_AGENT_NAME_POSTFIX_LEN 32

/**
 * Maximum allowed access key id length https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html
 */
#define MAX_ACCESS_KEY_LEN 128

/**
 * Maximum allowed secret access key length
 */
#define MAX_SECRET_KEY_LEN 128

/**
 * Maximum allowed session token string length
 */
#define MAX_SESSION_TOKEN_LEN 2048

/**
 * Maximum allowed expiration string length
 */
#define MAX_EXPIRATION_LEN 128

/**
 * Maximum allowed role alias length https://docs.aws.amazon.com/iot/latest/apireference/API_UpdateRoleAlias.html
 */
#define MAX_ROLE_ALIAS_LEN 128

/**
 * Maximum allowed string length for IoT thing name
 */
#define MAX_IOT_THING_NAME_LEN MAX_STREAM_NAME_LEN

/**
 * Maximum allowed request header length
 */
#define MAX_REQUEST_HEADER_NAME_LEN 128

/**
 * Maximum allowed header value length
 */
#define MAX_REQUEST_HEADER_VALUE_LEN 2048

/**
 * Maximum request header length in chars including the name/value, delimiter and null terminator
 */
#define MAX_REQUEST_HEADER_STRING_LEN (MAX_REQUEST_HEADER_NAME_LEN + MAX_REQUEST_HEADER_VALUE_LEN + 3)

/**
 * Maximum length of the credentials file
 */
#define MAX_CREDENTIAL_FILE_LEN MAX_AUTH_LEN

/**
 * Buffer length for the error to be stored in
 */
#define CALL_INFO_ERROR_BUFFER_LEN 256

/**
 * Max parameter JSON string len which will be used for preparing the parameterized strings for the API calls.
 */
#define MAX_JSON_PARAMETER_STRING_LEN (10 * 1024)
/*!@} */

/**
 * Default Video track ID to be used
 */
#define DEFAULT_VIDEO_TRACK_ID 1

/**
 * Default Audio track ID to be used
 */
#define DEFAULT_AUDIO_TRACK_ID 2

/**
 * Default period for the cached endpoint update
 */
#define DEFAULT_ENDPOINT_CACHE_UPDATE_PERIOD (40 * HUNDREDS_OF_NANOS_IN_A_MINUTE)

/**
 * Sentinel value indicating to use default update period
 */
#define ENDPOINT_UPDATE_PERIOD_SENTINEL_VALUE 0

/**
 * Max period for the cached endpoint update
 */
#define MAX_ENDPOINT_CACHE_UPDATE_PERIOD (24 * HUNDREDS_OF_NANOS_IN_AN_HOUR)

/////////////////////////////////////////////////////
/// Environment variables
/////////////////////////////////////////////////////

/*! \addtogroup EnvironmentVariables
 * Environment variable name
 *  @{
 */

/**
 * AWS Access Key value. Run `export AWS_ACCESS_KEY_ID=<value>` to provide AWS access key
 */
#define ACCESS_KEY_ENV_VAR ((PCHAR) "AWS_ACCESS_KEY_ID")

/**
 * AWS Secret Key value. Run `export AWS_SECRET_ACCESS_KEY=<value>` to provide AWS secret key
 */
#define SECRET_KEY_ENV_VAR ((PCHAR) "AWS_SECRET_ACCESS_KEY")

/**
 * AWS Session token value. Run `export AWS_SESSION_TOKEN=<value>` to provide AWS session token
 */
#define SESSION_TOKEN_ENV_VAR ((PCHAR) "AWS_SESSION_TOKEN")

/**
 * Closest AWS region to run Producer SDK. Run `export AWS_DEFAULT_REGION=<value>` to provide AWS region
 */
#define DEFAULT_REGION_ENV_VAR ((PCHAR) "AWS_DEFAULT_REGION")

/**
 * KVS CA Cert path. Provide this path if a cert is available in a path other than default. Run
 * `export AWS_KVS_CACERT_PATH=<value>` to provide Cert path
 */
#define CACERT_PATH_ENV_VAR ((PCHAR) "AWS_KVS_CACERT_PATH")

/**
 * KVS log level. KVS provides 7 log levels. Run `export AWS_KVS_LOG_LEVEL=<value>` to select log level
 */
#define DEBUG_LOG_LEVEL_ENV_VAR ((PCHAR) "AWS_KVS_LOG_LEVEL")

/**
 * Environment variable to enable file logging. Run export AWS_ENABLE_FILE_LOGGING=TRUE to enable file
 * logging
 */
#define ENABLE_FILE_LOGGING ((PCHAR) "AWS_ENABLE_FILE_LOGGING")
/*!@} */

#ifdef CMAKE_DETECTED_CACERT_PATH
#define DEFAULT_KVS_CACERT_PATH KVS_CA_CERT_PATH
#else
#define DEFAULT_KVS_CACERT_PATH EMPTY_STRING
#endif

/////////////////////////////////////////////////////
/// String constants
/////////////////////////////////////////////////////

/*! \addtogroup StringConstants
 * Fixed string defines
 *  @{
 */

/**
 * HTTPS Protocol scheme name
 */
#define HTTPS_SCHEME_NAME "https"

/**
 * WSS Protocol scheme name
 */
#define WSS_SCHEME_NAME "wss"

/**
 * HTTP GET request string
 */
#define HTTP_REQUEST_VERB_GET_STRING (PCHAR) "GET"
/**
 * HTTP PUT request string
 */
#define HTTP_REQUEST_VERB_PUT_STRING (PCHAR) "PUT"
/**
 * HTTP POST request string
 */
#define HTTP_REQUEST_VERB_POST_STRING (PCHAR) "POST"

/**
 * Schema delimiter string
 */
#define SCHEMA_DELIMITER_STRING (PCHAR) "://"

/**
 * Default canonical URI if we fail to get anything from the parsing
 */
#define DEFAULT_CANONICAL_URI_STRING (PCHAR) "/"

/**
 * Default AWS region
 */
#define DEFAULT_AWS_REGION "us-west-2"

/**
 * Control plane prefix
 */
#define CONTROL_PLANE_URI_PREFIX "https://"

/**
 * KVS service name
 */
#define KINESIS_VIDEO_SERVICE_NAME "kinesisvideo"

/**
 * Control plane postfix
 */
#define CONTROL_PLANE_URI_POSTFIX ".amazonaws.com"

/**
 * Default user agent name
 */
#define DEFAULT_USER_AGENT_NAME "AWS-SDK-KVS"

/**
 * Parameterized string for each tag pair
 */
#define TAG_PARAM_JSON_TEMPLATE "\n\t\t\"%s\": \"%s\","

/**
 * Header delimiter for requests and it's size
 */
#define REQUEST_HEADER_DELIMITER ((PCHAR) ": ")

/**
 * AWS service Request id header name
 */
#define KVS_REQUEST_ID_HEADER_NAME "x-amzn-RequestId"
/*!@} */

/////////////////////////////////////////////////////
/// Limits and counts
/////////////////////////////////////////////////////

/*! \addtogroup Limits
 * Limits and count macros
 *  @{
 */

// Max header count
#define MAX_REQUEST_HEADER_COUNT 200

// Max delimiter characters when packing headers into a string for printout
#define MAX_REQUEST_HEADER_OUTPUT_DELIMITER 5

// HTTP status OK
#define HTTP_STATUS_CODE_OK 200

// HTTP status Request timed out
#define HTTP_STATUS_CODE_REQUEST_TIMEOUT 408

/**
 * Max number of tokens in the API return JSON
 */
#define MAX_JSON_TOKEN_COUNT 100

/**
 * Low speed limits in bytes per duration
 */
#define DEFAULT_LOW_SPEED_LIMIT 30

/**
 * Low speed limits in 100ns for the amount of bytes per this duration
 */
#define DEFAULT_LOW_SPEED_TIME_LIMIT (30 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define REQUEST_HEADER_DELIMITER_SIZE (2 * SIZEOF(CHAR))
/*!@} */

/////////////////////////////////////////////////////
/// Miscellaneous
/////////////////////////////////////////////////////

/*! \addtogroup Miscellaneous
 * Miscellaneous macros
 *  @{
 */

/**
 * Current versions for the public structs
 */
#define AWS_CREDENTIALS_CURRENT_VERSION 0

/**
 * Default SSL port
 */
#define DEFAULT_SSL_PORT_NUMBER 443

/**
 * Default non-SSL port
 */
#define DEFAULT_NON_SSL_PORT_NUMBER 8080
/*!@} */

////////////////////////////////////////////////////
/// Main enum declarations
////////////////////////////////////////////////////
/*! \addtogroup PubicEnums
 *
 * @{
 */

/**
 * @brief Types of verbs
 */
typedef enum {
    HTTP_REQUEST_VERB_GET,  //!< Indicates GET type of HTTP request
    HTTP_REQUEST_VERB_POST, //!< Indicates POST type of HTTP request
    HTTP_REQUEST_VERB_PUT   //!< Indicates PUT type of HTTP request
} HTTP_REQUEST_VERB;

/**
 * @brief Request SSL certificate type Not specified, "DER", "PEM", "ENG"
 */
typedef enum {
    SSL_CERTIFICATE_TYPE_NOT_SPECIFIED, //!< Default enum when type of certificate is not specified
    SSL_CERTIFICATE_TYPE_DER,           //!< Use DER type of SSL certificate if certificate to use is *.der
    SSL_CERTIFICATE_TYPE_PEM,           //!< Use PEM type of SSL certificate if certificate to use is *.pem
    SSL_CERTIFICATE_TYPE_ENG,           //!< Use ENG type of SSL certificate if certificate to use is *.eng
} SSL_CERTIFICATE_TYPE;
/*!@} */

/////////////////////////////////////////////////////
/// Structures available for use by applications
/////////////////////////////////////////////////////

/*! \addtogroup PublicStructures
 *
 * @{
 */

/**
 * @brief AWS Credentials declaration
 */
typedef struct __AwsCredentials AwsCredentials;
struct __AwsCredentials {
    UINT32 version;         //!< Version of structure
    UINT32 size;            //!< Size of the entire structure in bytes including the struct itself
    PCHAR accessKeyId;      //!< Access Key ID - NULL terminated
    UINT32 accessKeyIdLen;  //!< Length of the access key id - not including NULL terminator
    PCHAR secretKey;        //!< Secret Key - NULL terminated
    UINT32 secretKeyLen;    //!< Length of the secret key - not including NULL terminator
    PCHAR sessionToken;     //!< Session token - NULL terminated
    UINT32 sessionTokenLen; //!< Length of the session token - not including NULL terminator
    UINT64 expiration;      //!< Expiration in absolute time in 100ns.
    //!< The rest of the data might follow the structure
};
typedef struct __AwsCredentials* PAwsCredentials;

/**
 * @brief Request Header structure
 */
typedef struct __RequestHeader RequestHeader;
struct __RequestHeader {
    PCHAR pName;     //!< Request header name
    UINT32 nameLen;  //!< Header name length
    PCHAR pValue;    //!< Request header value
    UINT32 valueLen; //!< Header value length
};
typedef struct __RequestHeader* PRequestHeader;

/**
 * @brief Request info structure
 */
typedef struct __RequestInfo RequestInfo;
struct __RequestInfo {
    volatile ATOMIC_BOOL terminating;         //!< Indicating whether the request is being terminated
    HTTP_REQUEST_VERB verb;                   //!< HTTP verb
    PCHAR body;                               //!< Body of the request.
                                              //!< NOTE: In streaming mode the body will be NULL
                                              //!< NOTE: The body will follow the main struct
    UINT32 bodySize;                          //!< Size of the body in bytes
    CHAR url[MAX_URI_CHAR_LEN + 1];           //!< The URL for the request
    CHAR certPath[MAX_PATH_LEN + 1];          //!< CA Certificate path to use - optional
    CHAR sslCertPath[MAX_PATH_LEN + 1];       //!< SSL Certificate file path to use - optional
    CHAR sslPrivateKeyPath[MAX_PATH_LEN + 1]; //!< SSL Certificate private key file path to use - optional
    SSL_CERTIFICATE_TYPE certType;            //!< One of the following types "DER", "PEM", "ENG"
    CHAR region[MAX_REGION_NAME_LEN + 1];     //!< Region
    UINT64 currentTime;                       //!< Current time when request was created
    UINT64 completionTimeout;                 //!< Call completion timeout
    UINT64 connectionTimeout;                 //!< Connection completion timeout
    UINT64 callAfter;                         //!< Call after time
    UINT64 lowSpeedLimit;                     //!< Low-speed limit
    UINT64 lowSpeedTimeLimit;                 //!< Low-time limit
    PAwsCredentials pAwsCredentials;          //!< AWS Credentials
    PSingleList pRequestHeaders;              //!< Request headers
};
typedef struct __RequestInfo* PRequestInfo;

/**
 * @brief Call Info structure
 */
typedef struct __CallInfo CallInfo;
struct __CallInfo {
    PRequestInfo pRequestInfo;                        //!< Original request info
    UINT32 httpStatus;                                //!< HTTP status code of the execution
    SERVICE_CALL_RESULT callResult;                   //!< Execution result
    CHAR errorBuffer[CALL_INFO_ERROR_BUFFER_LEN + 1]; //!< Error buffer for curl calls
    PStackQueue pResponseHeaders;                     //!< Response Headers list
    PRequestHeader pRequestId;                        //!< Request ID if specified
    PCHAR responseData;                               //!< Buffer to write the data to - will be allocated. Buffer is freed by a caller.
    UINT32 responseDataLen;                           //!< Response data size
};
typedef struct __CallInfo* PCallInfo;

/**
 * @brief Abstract base for the credential provider
 */
typedef struct __AwsCredentialProvider* PAwsCredentialProvider;

/*! \addtogroup Callbacks
 * Callback definitions
 *  @{
 */

/**
 * @brief Function returning AWS credentials
 */
typedef STATUS (*GetCredentialsFunc)(PAwsCredentialProvider, PAwsCredentials*);
/*!@} */

typedef struct __AwsCredentialProvider AwsCredentialProvider;
struct __AwsCredentialProvider {
    GetCredentialsFunc getCredentialsFn; //!< Get credentials function which will be overwritten by different implementations
};
/*!@} */

////////////////////////////////////////////////////
/// Public functions
////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_COMMON_INCLUDE__ */
