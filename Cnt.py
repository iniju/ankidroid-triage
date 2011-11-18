import logging
from google.appengine.api import memcache
from google.appengine.ext import db

class Cnt(db.Model):
	count = db.IntegerProperty(required=True, indexed=False)
	@classmethod
	def get(cls, name):
		count = memcache.get(name)
		if count is None:
			cnt = Cnt.get_by_key_name(name)
			if cnt is None:
				logging.warning("Cnt: returning None (%s)" % name)
				return cnt
			else:
				count = cnt.count
			memcache.set(name, count, 86400)
		logging.warning("Cnt: returning %d (%s)" % (count, name))
		return count
	@classmethod
	def incr(cls, name, value=1):
		cnt = Cnt.get_by_key_name(name)
		if cnt is None:
			cnt = Cnt(key_name=name, count=value)
			cnt.put()
		else:
			cnt.count += value
			cnt.put()
		memcache.set(name, cnt.count, 86400)
	@classmethod
	def set(cls, name, value):
		cnt = Cnt.get_by_key_name(name)
		if cnt is None:
			cnt = Cnt(key_name=name, count=value)
			cnt.put()
		else:
			cnt.count = value
			cnt.put()
		memcache.set(name, cnt.count, 86400)

