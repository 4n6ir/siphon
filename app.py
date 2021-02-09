#!/usr/bin/env python3

from aws_cdk import core

from siphon.siphon_stack import SiphonStack


app = core.App()
SiphonStack(app, "siphon")

app.synth()
