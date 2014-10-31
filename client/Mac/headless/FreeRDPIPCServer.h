//
//  FreeRDPIPCServer.h
//  FreeRDP
//
//  Created by Richard Markiewicz on 2014-10-31.
//
//

#import <Foundation/Foundation.h>

@protocol FreeRDPIPCServer <NSObject>
@required
- (NSString *)serverName;
- (NSString *)serverID;
- (void)clientConnected:(NSString *)clientName;
@optional
// list of optional methods
@end
