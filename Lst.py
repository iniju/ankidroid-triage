import logging
from google.appengine.api import memcache
from google.appengine.ext import db
import pickle
import zlib

class Lst(db.Model):
	blob = db.BlobProperty(required=True)
	@classmethod
	def get(cls, key):
		lst = Lst.get_by_key_name(key)
		if lst is None:
			return None
		data = zlib.decompress(lst.blob)
		return pickle.loads(data)
	@classmethod
	def set(cls, key, items, sortcmp=None):
		logging.warning("Sorting list - %s" % repr(sortcmp))
		if sortcmp:
			logging.warning("Sorting list - first: %s, last: %s" % (items[0], items[-1]))
			items.sort(cmp=sortcmp)
			logging.warning("Sorting list - first: %s, last: %s" % (items[0], items[-1]))
		data = pickle.dumps(items)
		data = zlib.compress(data)
		lst = Lst.get_by_key_name(key)
		if lst is None:
			lst = Lst(key_name=key, blob=db.Blob(data))
			lst.put()
		else:
			lst.blob = db.Blob(data)
			lst.put()
	@classmethod
	def append(cls, key, item, sortcmp=None):
		lst = Lst.get_by_key_name(key)
		if lst:
			data = pickle.loads(zlib.decompress(lst.blob))
			data.append(item)
			if sortcmp:
				data.sort(cmp=sortcmp)
				logging.warning("Sorting list - first: %s, last: %s" % (data[0], data[-1]))
			lst.blob = db.Blob(zlib.compress(pickle.dumps(data)))
			lst.put()
