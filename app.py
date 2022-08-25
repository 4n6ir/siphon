#!/usr/bin/env python3
import os

import aws_cdk as cdk

from siphon.siphon_parser import SiphonParser

from siphon.siphon_stack import SiphonStack

app = cdk.App()

SiphonStack(
    app, 'SiphonStack',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = os.getenv('CDK_DEFAULT_REGION')
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

#SiphonParser(
#    app, 'SiphonParser',
#    env = cdk.Environment(
#        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
#        region = os.getenv('CDK_DEFAULT_REGION')
#    ),
#    synthesizer = cdk.DefaultStackSynthesizer(
#        qualifier = '4n6ir'
#    )
#)

cdk.Tags.of(app).add('siphon','siphon')

app.synth()
