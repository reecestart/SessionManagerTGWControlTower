#!/usr/bin/env python3

from aws_cdk import core

from session_manager_tgw_control_tower.session_manager_tgw_control_tower_stack import SessionManagerTgwControlTowerStack


app = core.App()
SessionManagerTgwControlTowerStack(app, "session-manager-tgw-control-tower")

app.synth()
