
set(OPTION_DEFAULT OFF)
set(OPTION_CLIENT_DEFAULT OFF)
set(OPTION_SERVER_DEFAULT OFF)

if(WITH_PCSC OR WIN32)
	set(OPTION_CLIENT_DEFAULT ON)
	set(OPTION_SERVER_DEFAULT OFF)
endif()

define_channel_options(NAME "smartcard" TYPE "device"
	DESCRIPTION "Smart Card Virtual Channel Extension"
	SPECIFICATIONS "[MS-RDPESC]"
	DEFAULT ${OPTION_DEFAULT})

define_channel_client_options(${OPTION_CLIENT_DEFAULT})
define_channel_server_options(${OPTION_SERVER_DEFAULT})
