if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/aws/aws.h" AWS)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/aws/aws.cpp" AWS_CPP)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/aws/aws.http.cpp" SIGNER)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/aws/aws.transport.cpp" TRANSPORT)
file(READ "${PRODIGY_ROOT}/prodigy/dns/route53/route53.h" ROUTE53)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.pricing.h" PRICING)
file(READ "${PRODIGY_ROOT}/prodigy/brain/brain.h" BRAIN)
file(READ "${PRODIGY_ROOT}/prodigy/types.h" TYPES)
file(READ "${PRODIGY_ROOT}/depofiles/libcurl.DepoFile" LIBCURL)

foreach(FORBIDDEN IN ITEMS
      "curl_easy_"
      "curl_multi_"
      "curl_slist"
      "CURLOPT_AWS_SIGV4"
      "AwsHttp::"
      "AwsMetadataClient"
      "usleep(")
   string(FIND "${AWS}${AWS_CPP}${ROUTE53}" "${FORBIDDEN}" FOUND)
   if(NOT FOUND EQUAL -1)
      message(FATAL_ERROR "AWS provider/Route53 retains forbidden private transport or blocking surface: ${FORBIDDEN}")
   endif()
endforeach()

string(FIND "${PRICING}" "DescribeAvailabilityZones" LEGACY_AZ_DISCOVERY)
if(NOT LEGACY_AZ_DISCOVERY EQUAL -1)
   message(FATAL_ERROR "AWS pricing uses availability-zone discovery that can diverge from launch subnet placement")
endif()

foreach(FORBIDDEN IN ITEMS
      "curlx_dyn_set_secure"
      "http_aws_sigv4.c"
      "sensitive_sendbuf")
   string(FIND "${LIBCURL}" "${FORBIDDEN}" FOUND)
   if(NOT FOUND EQUAL -1)
      message(FATAL_ERROR "generic libcurl recipe contains AWS-consumer source patch: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "AwsHttpRequestImplementation"
      "OPENSSL_cleanse"
      "AwsHttpRequest::secureReset"
      "AwsHttpRequest::build")
   string(FIND "${SIGNER}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "AWS signer ownership contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "ProdigyHostHttpOperation operation"
      "ProdigyHostDelayOperation operation"
      "ProdigyHostSuspend"
      "169.254.169.254"
      "request.overallDeadline = operationDeadline"
      "maximumDiagnosticBytes"
      "AwsMetadataSession::get")
   string(FIND "${TRANSPORT}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "AWS async transport/IMDS contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "co_await transport.sendSigned"
      "route53.amazonaws.com"
      "MothershipAwsPricingHttp"
      "AwsHttpTransport::maximumPages"
      "ClientToken"
      "prodigy_launch_token"
      "compensateRunInstances"
      "configureProvisioningOperationID"
      "awsBootstrapLaunchTemplateDescription"
      "AvailabilityZone"
      "awsSelectBootstrapSubnet"
      "awsParseRFC3339Ms(timestamp, timestampMs)"
      "String desiredData"
      "pendingAutonomousProvisioningOperations"
      "configureProvisioningOperationID(provisioningOperationID)"
      "provisioningOperationSettled")
   string(FIND "${AWS}${ROUTE53}${PRICING}${BRAIN}${TYPES}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "AWS provider integration contract missing: ${REQUIRED}")
   endif()
endforeach()
