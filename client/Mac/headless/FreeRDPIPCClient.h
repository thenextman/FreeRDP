//
//  FreeRDPIPCClient.h
//  FreeRDP
//
//  Created by Richard Markiewicz on 2014-10-31.
//
//

#import <Foundation/Foundation.h>

@interface FreeRDPIPCClient : NSObject
{
    NSConnection *serverConnection;
}

- (void)initialiseWithServer:(NSString *)registeredName;
- (void)test:(NSString *)testString;

@property (nonatomic, retain) NSConnection *serverConnection;

@end
