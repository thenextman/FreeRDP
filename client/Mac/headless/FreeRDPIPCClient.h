//
//  FreeRDPIPCClient.h
//  FreeRDP
//
//  Created by Richard Markiewicz on 2014-10-31.
//
//

#import <Foundation/Foundation.h>
#import "MacFreeRDP/mfreerdp.h"
#import "MRDPClient.h"

@interface FreeRDPIPCClient : NSObject
{
    NSConnection *serverConnection;
    rdpContext *context;
    MRDPClient *mrdpClient;
}

- (void)initialiseWithServer:(NSString *)registeredName;
- (void)configure;
- (void)start;
- (void)stop;
- (void)restart;
- (BOOL)getBooleanSettingForIdentifier:(int)identifier;
- (int)setBooleanSettingForIdentifier:(int)identifier withValue:(BOOL)value;
- (int)getIntegerSettingForIdentifier:(int)identifier;
- (int)setIntegerSettingForIdentifier:(int)identifier withValue:(int)value;
- (uint32)getInt32SettingForIdentifier:(int)identifier;
- (int)setInt32SettingForIdentifier:(int)identifier withValue:(uint32)value;
- (uint64)getInt64SettingForIdentifier:(int)identifier;
- (int)setInt64SettingForIdentifier:(int)identifier withValue:(uint64)value;
- (NSString *)getStringSettingForIdentifier:(int)identifier;
- (int)setStringSettingForIdentifier:(int)identifier withValue:(NSString *)value;
- (double)getDoubleSettingForIdentifier:(int)identifier;
- (int)setDoubleSettingForIdentifier:(int)identifier withValue:(double)value;

@property (nonatomic, retain) NSConnection *serverConnection;
@property (assign) rdpContext *context;


@end
