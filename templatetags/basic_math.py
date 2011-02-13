# ###
# Copyright (c) 2010 Konstantinos Spyropoulos <inigo.aldana@gmail.com>
#
# This file is part of ankidroid-triage
#
# ankidroid-triage is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# ankidroid-triage is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with ankidroid-triage.
# If not, see http://www.gnu.org/licenses/.
# #####

from google.appengine.ext import webapp
register = webapp.template.create_template_register()

def gt(a, b):
	return a > b

def lt(a, b):
	return a < b

def gte(a, b):
	return a >= b

def lte(a, b):
	return a <= b

def sub(a, b):
	return int(a) - int(b)

def mul(a, b):
	return int(a) * int(b)

def div(a, b):
	return int(a) / int(b)

def divtrunc(a, b):
	return int(a) // int(b)

def mod(a, b):
	return int(a) % int(b)

def maxof(a, b):
	if a >= b:
		return a
	else:
		return b

def minof(a, b):
	if a <= b:
		return a
	else:
		return b

register.filter(gt)
register.filter(lt)
register.filter(gte)
register.filter(lte)
register.filter(sub)
register.filter(mul)
register.filter(div)
register.filter(divtrunc)
register.filter(mod)
register.filter(maxof)
register.filter(minof)

