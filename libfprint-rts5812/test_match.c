/* Offline harness for rts5812_match.c: extract features from each PGM given on
 * the command line and print every pairwise score, plus timing.
 *   gcc -O2 test_match.c rts5812_match.c $(pkg-config --cflags --libs glib-2.0) -lm
 *   ./a.out ../dataset2/frame_*.pgm */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rts5812_match.h"

static guint8 *
read_pgm (const char *p, int *w, int *h)
{
  FILE *f = fopen (p, "rb");
  char m[3] = { 0 };
  int maxv;
  guint8 *b;

  if (!f)
    return NULL;
  if (fscanf (f, "%2s %d %d %d", m, w, h, &maxv) != 4 || strcmp (m, "P5"))
    {
      fclose (f);
      return NULL;
    }
  fgetc (f);
  b = g_malloc ((gsize) *w * *h);
  if (fread (b, 1, (gsize) *w * *h, f) != (gsize) *w * *h)
    g_clear_pointer (&b, g_free);
  fclose (f);
  return b;
}

int
main (int argc, char **argv)
{
  int n = argc - 1;
  Rts5812Features **F = g_new0 (Rts5812Features *, n);
  gint64 t0 = g_get_monotonic_time ();

  for (int i = 0; i < n; i++)
    {
      int w, h;
      g_autofree guint8 *img = read_pgm (argv[i + 1], &w, &h);
      if (!img)
        {
          fprintf (stderr, "cannot read %s\n", argv[i + 1]);
          return 2;
        }
      F[i] = rts5812_features_extract (img, w, h);
      printf ("M %s %d\n", argv[i + 1], rts5812_features_count (F[i]));
    }
  gint64 t1 = g_get_monotonic_time ();
  int pairs = 0;
  for (int i = 0; i < n; i++)
    for (int j = i + 1; j < n; j++, pairs++)
      printf ("S %d %d %d\n", i, j, rts5812_features_match (F[i], F[j]));
  gint64 t2 = g_get_monotonic_time ();
  fprintf (stderr, "extract %.1f ms/frame, match %.1f ms/pair\n",
           (t1 - t0) / 1000.0 / MAX (n, 1), (t2 - t1) / 1000.0 / MAX (pairs, 1));
  for (int i = 0; i < n; i++)
    rts5812_features_free (F[i]);
  g_free (F);
  return 0;
}
