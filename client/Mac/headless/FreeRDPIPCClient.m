//
//  FreeRDPIPCClient.m
//  FreeRDP
//
//  Created by Richard Markiewicz on 2014-10-31.
//
//

#import "FreeRDPIPCClient.h"
#import "FreeRDPIPCServer.h"

@implementation FreeRDPIPCClient

static NSString* const clientBaseName = @"com.devolutions.freerdpclient";

@synthesize serverConnection = serverConnection;

- (void)initialiseWithServer:(NSString *)registeredName
{
    id hostProxy = (id)[NSConnection rootProxyForConnectionWithRegisteredName:registeredName host:nil];
    [hostProxy setProtocolForProxy:@protocol(FreeRDPIPCServer)];
    
    if(hostProxy != nil)
    {
        NSString *serverID = [hostProxy serverID];
        NSString *clientName = [NSString stringWithFormat:@"%@.%@", clientBaseName, serverID];
        
        serverConnection = [NSConnection serviceConnectionWithName:clientName rootObject:self];
        [serverConnection registerName:clientName];
        
        [hostProxy clientConnected:clientName];
    }
}

- (void)test:(NSString *)testString
{
    printf("you said: %s", [testString UTF8String]);
}

@end
