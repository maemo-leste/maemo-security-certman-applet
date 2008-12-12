/**
   @file password.h

   Password functions for the Certificate Manager CPA.
   <p>
   Copyright (c) 2006 Nokia. All rights reserved.

   @author  Jakub Pavelek <jakub.pavelek@nokia.com>
*/


/**
   Ask for a new password.

   @param new_passwd1           A pointer to a string, wehere newly allocated
   string representing the new password is saved.
   @param old_was_asked         TRUE if old password was asked in dialog 1/3.
   Based on this dialogs are numbered as either
   as (2/3 and 3/3) or (1/2 and 2/2).

   @return FALSE, if process was quit.
*/
gboolean ask_for_new_password(gpointer window, gchar** new_passwd1,
                              gboolean old_was_asked);
