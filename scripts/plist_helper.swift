// plist_helper.swift
// Batch rule writer for LuLu firewall.
//
// Reads a JSON payload from stdin, applies all adds and removes in a single
// plist read-modify-write cycle, then prints a JSON result to stdout.
//
// Input JSON:
//   {
//     "add":          [{"addr": "1.2.3.4", "uuid": "AAAA-..."}, ...],
//     "remove":       ["UUID1", "UUID2", ...],
//     "clear_managed": false
//   }
//
// Output JSON:
//   {"ok": true, "added": 5, "removed": 3}
//
// The Rule class below is a verbatim mirror of the class in woop/lulu-cli so
// NSKeyedArchiver produces a plist that LuLu and lulu-cli can both read back.

import Foundation

// ---------------------------------------------------------------------------
// Rule — mirrors woop/lulu-cli exactly (NSSecureCoding, same encode keys)
// ---------------------------------------------------------------------------

@objc(Rule)
class Rule: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    @objc var uuid: String?
    @objc var key: String?
    @objc var pid: NSNumber?
    @objc var path: String?
    @objc var name: String?
    @objc var csInfo: NSDictionary?
    @objc var endpointAddr: String?
    @objc var endpointHost: String?
    @objc var isEndpointAddrRegex: Bool = false
    @objc var endpointPort: String?
    @objc var type: NSNumber?
    @objc var scope: NSNumber?
    @objc var action: NSNumber?
    @objc var isDisabled: NSNumber?
    @objc var creation: Date?
    @objc var expiration: Date?

    override init() { super.init() }

    required init?(coder decoder: NSCoder) {
        super.init()
        key              = decoder.decodeObject(of: NSString.self, forKey: "key") as String?
        uuid             = decoder.decodeObject(of: NSString.self, forKey: "uuid") as String?
        pid              = decoder.decodeObject(of: NSNumber.self, forKey: "pid")
        path             = decoder.decodeObject(of: NSString.self, forKey: "path") as String?
        name             = decoder.decodeObject(of: NSString.self, forKey: "name") as String?
        csInfo           = decoder.decodeObject(of: [NSDictionary.self, NSArray.self,
                                                      NSString.self, NSNumber.self],
                                                forKey: "csInfo") as? NSDictionary
        isEndpointAddrRegex = decoder.decodeBool(forKey: "isEndpointAddrRegex")
        endpointAddr     = decoder.decodeObject(of: NSString.self, forKey: "endpointAddr") as String?
        endpointHost     = decoder.decodeObject(of: NSString.self, forKey: "endpointHost") as String?
        endpointPort     = decoder.decodeObject(of: NSString.self, forKey: "endpointPort") as String?
        type             = decoder.decodeObject(of: NSNumber.self, forKey: "type")
        scope            = decoder.decodeObject(of: NSNumber.self, forKey: "scope")
        action           = decoder.decodeObject(of: NSNumber.self, forKey: "action")
        isDisabled       = decoder.decodeObject(of: NSNumber.self, forKey: "isDisabled")
        creation         = decoder.decodeObject(of: NSDate.self,   forKey: "creation") as Date?
        expiration       = decoder.decodeObject(of: NSDate.self,   forKey: "expiration") as Date?
    }

    func encode(with encoder: NSCoder) {
        encoder.encode(key,                  forKey: "key")
        encoder.encode(uuid,                 forKey: "uuid")
        encoder.encode(pid,                  forKey: "pid")
        encoder.encode(path,                 forKey: "path")
        encoder.encode(name,                 forKey: "name")
        encoder.encode(csInfo,               forKey: "csInfo")
        encoder.encode(isEndpointAddrRegex,  forKey: "isEndpointAddrRegex")
        encoder.encode(endpointAddr,         forKey: "endpointAddr")
        encoder.encode(endpointHost,         forKey: "endpointHost")
        encoder.encode(endpointPort,         forKey: "endpointPort")
        encoder.encode(type,                 forKey: "type")
        encoder.encode(scope,                forKey: "scope")
        encoder.encode(action,               forKey: "action")
        encoder.encode(isDisabled,           forKey: "isDisabled")
        encoder.encode(creation,             forKey: "creation")
        encoder.encode(expiration,           forKey: "expiration")
    }
}

// ---------------------------------------------------------------------------
// Constants (matching lulu-cli)
// ---------------------------------------------------------------------------

let RULES_FILE   = "/Library/Objective-See/LuLu/rules.plist"
let MANAGED_KEY  = "com.lulu-rules.c2-feeds"
let KEY_RULES    = "rules"

let RULE_STATE_BLOCK:     NSNumber = 0
let RULE_TYPE_USER:       NSNumber = 3
let ACTION_SCOPE_ENDPOINT: NSNumber = 1

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fail(_ message: String) -> Never {
    fputs("error: \(message)\n", stderr)
    exit(1)
}

func jsonOut(_ obj: Any) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj),
          let str  = String(data: data, encoding: .utf8) else {
        fail("could not serialise output JSON")
    }
    print(str)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// 1. Read and parse stdin JSON
let inputData = FileHandle.standardInput.readDataToEndOfFile()
guard !inputData.isEmpty,
      let input = try? JSONSerialization.jsonObject(with: inputData) as? [String: Any]
else {
    fail("could not parse JSON from stdin")
}

let toAddSpecs    = input["add"]           as? [[String: String]] ?? []
let toRemoveUUIDs = Set(input["remove"]    as? [String]           ?? [])
let clearManaged  = input["clear_managed"] as? Bool               ?? false

// 2. Load existing rules plist (or start fresh)
var rulesDict: NSMutableDictionary

let rulesClasses: [AnyClass] = [
    NSDictionary.self, NSMutableDictionary.self,
    NSArray.self, NSMutableArray.self,
    NSString.self, NSNumber.self,
    NSDate.self, Rule.self
]

if let rawData = try? Data(contentsOf: URL(fileURLWithPath: RULES_FILE)),
   let unarchived = try? NSKeyedUnarchiver.unarchivedObject(ofClasses: rulesClasses, from: rawData),
   let dict = unarchived as? NSDictionary {
    rulesDict = dict.mutableCopy() as! NSMutableDictionary
} else {
    rulesDict = NSMutableDictionary()
}

// 3. Optionally wipe all existing managed rules (--force-rebuild)
if clearManaged {
    rulesDict.removeObject(forKey: MANAGED_KEY)
}

// 4. Build a mutable array of existing managed rules, minus any to remove
let managedRules = NSMutableArray()
if let existingEntry = rulesDict[MANAGED_KEY] as? NSDictionary,
   let existingRules = existingEntry[KEY_RULES] as? NSArray {
    for item in existingRules {
        if let rule = item as? Rule,
           let ruleUUID = rule.uuid,
           !toRemoveUUIDs.contains(ruleUUID) {
            managedRules.add(rule)
        }
    }
}
let removedCount = (rulesDict[MANAGED_KEY] as? NSDictionary).flatMap {
    ($0[KEY_RULES] as? NSArray)?.count
}.map { $0 - managedRules.count } ?? 0

// 5. Append new rules
let now = Date()
for spec in toAddSpecs {
    guard let addr = spec["addr"], let ruleUUID = spec["uuid"] else { continue }
    let rule              = Rule()
    rule.uuid             = ruleUUID
    rule.key              = MANAGED_KEY
    rule.name             = "lulu-rules"   // LuLu's UI passes this to setStringValue: — must not be nil
    rule.path             = "*"
    rule.action           = RULE_STATE_BLOCK
    rule.type             = RULE_TYPE_USER
    rule.scope            = ACTION_SCOPE_ENDPOINT
    rule.endpointAddr     = addr
    rule.endpointHost     = addr           // also displayed in the rules table — must not be nil
    rule.endpointPort     = "*"
    rule.creation         = now
    managedRules.add(rule)
}

// 6. Store updated entry back
let entry = NSMutableDictionary()
entry[KEY_RULES] = managedRules
rulesDict[MANAGED_KEY] = entry

// 7. Write plist atomically
do {
    let data = try NSKeyedArchiver.archivedData(withRootObject: rulesDict,
                                                requiringSecureCoding: true)
    try data.write(to: URL(fileURLWithPath: RULES_FILE), options: .atomic)
} catch {
    fail("could not write rules plist: \(error)")
}

// 8. Report
jsonOut(["ok": true, "added": toAddSpecs.count, "removed": removedCount])
