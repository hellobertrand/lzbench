#ifndef XZK_H
#define XZK_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  // --- API de Streaming ---

  /**
   * Compresse les données lues depuis f_in vers f_out.
   * Utilise un pipeline asynchrone (Ring Buffer).
   * @param f_in      Flux d'entrée (ouvert en mode "rb")
   * @param f_out     Flux de sortie (ouvert en mode "wb")
   * @param n_threads Nombre de threads workers (0 = auto-détection cœurs)
   * @return          Nombre total d'octets compressés écrits, ou -1 en cas d'erreur.
   */
  int xzk_stream_compress(FILE *f_in, FILE *f_out, int n_threads);

  /**
   * Décompresse les données lues depuis f_in vers f_out.
   * @param f_in      Flux d'entrée (ouvert en mode "rb")
   * @param f_out     Flux de sortie (ouvert en mode "wb")
   * @param n_threads Nombre de threads workers (0 = auto-détection cœurs)
   * @return          Nombre total d'octets décompressés écrits, ou -1 en cas d'erreur.
   */
  int xzk_stream_decompress(FILE *f_in, FILE *f_out, int n_threads);

  // --- Utilitaires ---

  /**
   * Calcule la taille maximale théorique du buffer de sortie pour une taille d'entrée donnée.
   * Utile pour les allocations manuelles.
   */
  size_t xzk_max_compressed_size(size_t input_size);

#ifdef __cplusplus
}
#endif

#endif // XZK_H