#  Copyright (C) 2015  Stanislav Sinyagin
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

#

SUBST = @abs_top_builddir@/setup_tools/substvars.sh

bin_SCRIPTS = \
	rring \
	rring_run_test

CLEANFILES = $(bin_SCRIPTS)

EXTRA_DIST = \
	rring.in \
	rring_run_test.in


rring: rring.in
	$(SUBST) rring.in > rring

rring_run_test: rring_run_test.in
	$(SUBST) rring_run_test.in > rring_run_test
