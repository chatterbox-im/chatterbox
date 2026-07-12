// SystemConfigurationStubs.c
//
// hickory-resolver (the DNS crate used by tokio-xmpp) links against
// SystemConfiguration.framework APIs that are macOS-only and absent from the
// iOS SDK.  These stub implementations satisfy the linker.  They return
// NULL/false so hickory-resolver falls back to its built-in default DNS
// servers (8.8.8.8 / 8.8.4.4) instead of reading system DNS config.
//
// The iOS-available Reachability symbols (SCNetworkReachability*) are
// provided by the real SystemConfiguration.framework linked via
// OTHER_LDFLAGS = -framework SystemConfiguration.

#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>

// SCDynamicStore (not on iOS)
//
// Return a non-NULL sentinel for the store handle so hickory-resolver
// proceeds past the NULL-check and reaches SCDynamicStoreCopyValue.
static int _stub_dynamic_store = 0;
CFDictionaryRef SCDynamicStoreCopyProxies(void *store) { return NULL; }

CFPropertyListRef SCDynamicStoreCopyValue(void *store, CFStringRef key) {
    // Provide a minimal DNS config so hickory-resolver can resolve hostnames.
    // Without this it gets zero nameservers and all hostname lookups time out.
    if (key != NULL &&
        CFStringCompare(key, CFSTR("State:/Network/Global/DNS"), 0) == kCFCompareEqualTo) {
        CFStringRef addrs[2] = { CFSTR("8.8.8.8"), CFSTR("8.8.4.4") };
        CFArrayRef servers = CFArrayCreate(NULL, (const void **)addrs, 2, &kCFTypeArrayCallBacks);
        CFStringRef dnsKey = CFSTR("ServerAddresses");
        CFDictionaryRef result = CFDictionaryCreate(NULL,
            (const void **)&dnsKey, (const void **)&servers, 1,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFRelease(servers);
        return result;
    }
    return NULL;
}

void *SCDynamicStoreCreateRunLoopSource(CFAllocatorRef alloc, void *store, CFIndex order) { return NULL; }
void *SCDynamicStoreCreateWithOptions(CFAllocatorRef alloc, CFStringRef name, CFDictionaryRef options, void *callback, void *context) {
    return &_stub_dynamic_store;   // non-NULL sentinel
}

// SCNetworkInterface (not on iOS)
CFArrayRef  SCNetworkInterfaceCopyAll(void) { return NULL; }
CFStringRef SCNetworkInterfaceGetBSDName(void *iface) { return NULL; }
CFStringRef SCNetworkInterfaceGetInterfaceType(void *iface) { return NULL; }
CFStringRef SCNetworkInterfaceGetLocalizedDisplayName(void *iface) { return NULL; }

// SCNetworkService (not on iOS)
CFArrayRef  SCNetworkServiceCopyAll(void *prefs) { return NULL; }
bool        SCNetworkServiceGetEnabled(void *service) { return false; }
void       *SCNetworkServiceGetInterface(void *service) { return NULL; }
CFStringRef SCNetworkServiceGetServiceID(void *service) { return NULL; }

// SCNetworkSet (not on iOS)
void       *SCNetworkSetCopyCurrent(void *prefs) { return NULL; }
CFArrayRef  SCNetworkSetGetServiceOrder(void *set) { return NULL; }

// SCPreferences (not on iOS)
void *SCPreferencesCreate(CFAllocatorRef alloc, CFStringRef name, CFStringRef prefsID) { return NULL; }

// String constants — returning NULL is safe because they're only compared
// against interface type strings returned by SCNetworkInterfaceGetInterfaceType,
// String constants — must be non-NULL CFStringRef values; core-foundation's
// Rust wrapper panics on NULL.  These stubs use unique sentinel strings so
// CFStringCompare calls against real values never accidentally match.
// They are safe because SCNetworkInterfaceGetInterfaceType() (above) returns
// NULL, so the comparison code is never actually reached at runtime.
const CFStringRef kSCDynamicStoreUseSessionKeys    = CFSTR("__stub_DynStoreSessionKeys__");
const CFStringRef kSCNetworkInterfaceType6to4      = CFSTR("__stub_6to4__");
const CFStringRef kSCNetworkInterfaceTypeBluetooth = CFSTR("__stub_Bluetooth__");
const CFStringRef kSCNetworkInterfaceTypeBond      = CFSTR("__stub_Bond__");
const CFStringRef kSCNetworkInterfaceTypeEthernet  = CFSTR("__stub_Ethernet__");
const CFStringRef kSCNetworkInterfaceTypeFireWire  = CFSTR("__stub_FireWire__");
const CFStringRef kSCNetworkInterfaceTypeIEEE80211 = CFSTR("__stub_IEEE80211__");
const CFStringRef kSCNetworkInterfaceTypeIPSec     = CFSTR("__stub_IPSec__");
const CFStringRef kSCNetworkInterfaceTypeIPv4      = CFSTR("__stub_IPv4__");
const CFStringRef kSCNetworkInterfaceTypeL2TP      = CFSTR("__stub_L2TP__");
const CFStringRef kSCNetworkInterfaceTypeModem     = CFSTR("__stub_Modem__");
const CFStringRef kSCNetworkInterfaceTypePPP       = CFSTR("__stub_PPP__");
const CFStringRef kSCNetworkInterfaceTypePPTP      = CFSTR("__stub_PPTP__");
const CFStringRef kSCNetworkInterfaceTypeSerial    = CFSTR("__stub_Serial__");
const CFStringRef kSCNetworkInterfaceTypeVLAN      = CFSTR("__stub_VLAN__");
const CFStringRef kSCNetworkInterfaceTypeWWAN      = CFSTR("__stub_WWAN__");
