/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* $Id$ */

/* Copyright (C) 1998-99 Martin Baulig
   This file is part of LibGTop 1.0.

   Contributed by Martin Baulig <martin@home-of-linux.org>, April 1998.

   LibGTop is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License,
   or (at your option) any later version.

   LibGTop is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
   for more details.

   You should have received a copy of the GNU General Public License
   along with LibGTop; see the file COPYING. If not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/

#include <glibtop.h>
#include <glibtop/error.h>
#include <glibtop/backend.h>

#include <glibtop-backend-private.h>

#ifndef DEBUG
#define DEBUG 1
#endif

void
glibtop_write_i (glibtop *server, glibtop_backend *backend,
		 size_t size, void *buf)
{
    int ret;

    if (size == 0) return;

#ifdef DEBUG
    fprintf (stderr, "LIBRARY: really writing %d bytes.\n", size);
#endif

    ret = write (backend->_priv->output [1], buf, size);

    if (ret < 0)
	glibtop_error_io_r (server, _("write %d bytes"), size);
}