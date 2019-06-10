# -*- coding: UTF-8 -*-
#! python3

"""
The flask application package.
"""

from flask import Flask

app = Flask(__name__)

import IsogeoFlask.views
