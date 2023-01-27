############################################################
#region debug
import { createLogFunctions } from "thingy-debug"
{log, olog} = createLogFunctions("authclientmodule")
#endregion

############################################################
import * as tbut from "thingy-byte-utils"
import  { Client}  from "./authclient.js"

############################################################
export createClient = (o) ->
    log "createClient"
    olog o
    ## TODO add some sophistication
    return new Client(o.serverURL, o.secretKeyHex)

############################################################
ensure32BytesHex = (key) ->
    # real code to check on client already
    if key instanceof Uint8Array
        if key.length != 32 then throw new Error("Invalid length!")
        key = tbut.bytesToHex(key)
    if typeof key != "string" then throw new Error("Invalid type, hexString or Uint8Array expected!")
    if key.charAt(1) == "x" then key = key.slice(2)
    if key.length != 64 then throw new Error("Invalid length!")
    for c in key when !hexMap[c]? then throw new Error("Non-hex character!")
    return key
