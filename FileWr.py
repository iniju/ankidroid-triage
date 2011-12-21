from __future__ import with_statement

import logging
from google.appengine.api import files
from google.appengine.ext import db
from google.appengine.ext import blobstore

class FileWr(db.Model):
	bkey = blobstore.BlobReferenceProperty(default=None)
	def append(self, filename, data):
		if self.bkey:
			blob_reader = blobstore.BlobReader(self.bkey)
		newblob = files.blobstore.create(mime_type='text/csv', _blobinfo_uploaded_filename=filename)
		with files.open(newblob, 'a') as f:
			if self.bkey:
				buf = blob_reader.read(1000000)
				while buf:
					f.write(buf)
					buf = blob_reader.read(1000000)
					logging.info("rewritting %d" % len(buf))
			f.write(data)
			logging.info("writing %d" % len(data))
		files.finalize(newblob)
		if self.bkey:
			self.bkey.delete()
		blobkey = files.blobstore.get_blob_key(newblob)
		self.bkey = blobkey
		self.put()
	def clear(self):
		self.bkey.delete()
		self.bkey = None
		self.put()
	def get(self):
		blob_reader = blobstore.BlobReader(self.bkey)
		return blob_reader.read()

