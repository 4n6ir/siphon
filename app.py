#!/usr/bin/env python3

import os

from aws_cdk import core

from siphon.siphon_stack import SiphonStack


app = core.App()

SiphonStack(
    app, 'siphon', env = core.Environment(
        account = os.environ['CDK_DEFAULT_ACCOUNT'],
        region = os.environ['CDK_DEFAULT_REGION']
    )
)

core.Tags.of(app).add('siphon', 'siphon')

app.synth()
