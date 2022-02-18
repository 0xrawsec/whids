#!/usr/bin/env python
import sys
import json
import argparse
import os

package = os.path.dirname((os.path.realpath(__file__))).split(os.path.sep)[-2]

def convert_type(t: str) -> str:
    return "[]Filter"
    '''if t in ["win:UnicodeString", "win:GUID"]:
        return "string"
    if t == "win:UInt32":
        return "uint32"
    if t == "win:HexInt32":
        return "int32"
    if t == "win:HexInt64":
        return "int64"
    if t == "win:Boolean":
        return "bool"
    if t == "win:UInt16":
        return "uint16"
    raise TypeError(t)'''

def emit_struct(d: dict) -> str:
    name = d["@rulename"]
    data = d["data"]
    out = [
        f"type {name} struct {{",
        "\tEventFilter",
    ]
    for d in data:
        fname = d["@name"]
        intype = convert_type(d["@inType"])
        out.append(f'\t{fname} {intype} `json:",omitempty"`')
    out.append("}")
    return "\n".join(out)

def emit_conditions(text: str) -> str:
    conditions = text.split(",")
    out = [
        "Conditions = []string{"
    ]
    for c in conditions:
        out.append(f'"{c}",')
    out.append("}")
    return "\n".join(out)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("JSON_SCHEMA", help="JSON schema generated with xq")

    args = parser.parse_args()

    if args.JSON_SCHEMA == "-":
        schema = json.load(sys.stdin)
    else:
        with open(args.JSON_SCHEMA) as fd:
            schema = json.load(fd)
    
    print(f"package {package}\n")
    
    print('''
    /*
    This file has been auto-generated, do not edit it directly
    as it may be overwritten in the future
    */
    \n''')

    # variables
    print("var (")
    print(emit_conditions(schema["manifest"]["configuration"]["filters"]["#text"]))
    print(")")


    done = []
    for event in schema["manifest"]["events"]["event"]:
        if "@rulename" not in event:
            continue
        if event["@rulename"] in done:
            continue
        struct = emit_struct(event)
        print(struct, end="\n\n")
        done.append(event["@rulename"])
    
    print("type Filters struct {")
    for t in done:
        print(f'{t} *{t} `xml:",omitempty" json:",omitempty"`')
    print("}")


