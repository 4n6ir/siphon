#!/usr/bin/env python3

import os

from aws_cdk import core as cdk

from siphon.siphon_stack import SiphonStack


app = cdk.App()
SiphonStack(
    app, 'siphon', env = cdk.Environment(
        account = os.environ['CDK_DEFAULT_ACCOUNT'],
        region = os.environ['CDK_DEFAULT_REGION']
    )
)


cdk.Tags.of(app).add('siphon', 'siphon')


app.synth()
