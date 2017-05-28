# -*- coding: utf-8 -*-
# Created on 2016/5/27
from __future__ import unicode_literals, absolute_import

from fomalhaut.utils import import_string

try:
    from fomalhaut.settings import LANGUAGE
except:
    LANGUAGE = 'zh-Hans'

PromptMessage = import_string('fomalhaut.i18n.%s.PromptMessage' % LANGUAGE.replace('-', '_'))

__all__ = ['PromptMessage']
