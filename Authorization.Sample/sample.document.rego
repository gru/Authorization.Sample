package sample.document

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input.object == "Document"
    
}