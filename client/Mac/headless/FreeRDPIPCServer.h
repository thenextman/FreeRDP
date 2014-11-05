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
- (void)rdpConnected:(int)fbSegmentId;
- (void)drawDirtyRect:(float)x Y:(float)y HEIGHT:(float)height WIDTH:(float)width;

@optional
// list of optional methods
@end
