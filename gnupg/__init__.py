""" A wrapper for the GnuPG `gpg` command.

Portions of this module are derived from A.M. Kuchling's well-designed
GPG.py, using Richard Jones' updated version 1.3, which can be found
in the pycrypto CVS repository on Sourceforge:

http://pycrypto.cvs.sourceforge.net/viewvc/pycrypto/gpg/GPG.py

This module is *not* forward-compatible with amk's; some of the
old interface has changed.  For instance, since I've added decrypt
functionality, I elected to initialize with a 'gnupghome' argument
instead of 'keyring', so that gpg can find both the public and secret
keyrings.  I've also altered some of the returned objects in order for
the caller to not have to know as much about the internals of the
result classes.

While the rest of ISconf is released under the GPL, I am releasing
this single file under the same terms that A.M. Kuchling used for
pycrypto.

Steve Traugott, stevegt@terraluna.org
Thu Jun 23 21:27:20 PDT 2005

This version of the module has been modified from Steve Traugott's version
(see http://trac.t7a.org/isconf/browser/trunk/lib/python/isconf/GPG.py) by
Vinay Sajip to make use of the subprocess module (Steve's version uses os.fork()
and so does not work on Windows). Renamed to gnupg.py to avoid confusion with
the previous versions.

Modifications Copyright (C) 2008-2024 Vinay Sajip. All rights reserved.

For the full documentation, see https://docs.red-dove.com/python-gnupg/ or
https://gnupg.readthedocs.io/
"""

from __future__ import annotations

from .gnupg import GPG

__version__ = "YANKED"
__author__ = "Vinay Sajip"
__date__ = "YANKED"

__all__ = ("GPG",)
