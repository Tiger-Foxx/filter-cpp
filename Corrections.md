 # Journal des corrections

## Erreur 1: Erreur de configuration de PCRE2

- **Erreur**: `PCRE2_CODE_UNIT_WIDTH must be defined before including pcre2.h`.
- **Cause**: La bibliothèque PCRE2 nécessite que la macro `PCRE2_CODE_UNIT_WIDTH` soit définie avant d'inclure l'en-tête `pcre2.h`.
- **Correction**: Ajout de `add_definitions(-DPCRE2_CODE_UNIT_WIDTH=8)` dans le fichier `CMakeLists.txt` pour définir la macro pour toutes les unités de compilation.

## Erreur 2: En-tête manquant pour `std::thread`

- **Erreur**: `‘thread’ is not a member of ‘std’`.
- **Cause**: Le fichier `utils.h` utilisait `std::thread` sans inclure l'en-tête `<thread>`.
- **Correction**: Ajout de `#include <thread>` dans `src/utils.h`.

## Erreur 3: `fetch_add` non disponible pour `std::atomic<double>`

- **Erreur**: `‘struct std::atomic<double>’ has no member named ‘fetch_add’`.
- **Cause**: `std::atomic<double>::fetch_add` n'est pas standard en C++17.
- **Correction**: Remplacement de `fetch_add` par une boucle `compare_exchange_weak` dans `src/utils.h` pour assurer l'atomicité.

## Erreur 4: `starts_with` non disponible en C++17

- **Erreur**: `‘const string’ has no member named ‘starts_with’`.
- **Cause**: La méthode `starts_with` a été introduite en C++20, et le projet utilise C++17.
- **Correction**: Remplacement de `starts_with` par `rfind(prefix, 0) == 0` dans `src/engine/rule_engine.cpp` et `src/utils.cpp`.

## Erreur 5: Erreurs `goto` et `crosses initialization`

- **Erreur**: `jump to label ... crosses initialization of ...`.
- **Cause**: Utilisation de `goto` qui saute par-dessus des initialisations de variables.
- **Correction**: Refactorisation des méthodes `EvaluateSequential` et `EvaluateSequentialHyb` dans `src/engine/sequential_engine.cpp` et `src/engine/sequential_hyb_engine.cpp` pour éliminer les `goto`.

## Erreur 6: Erreurs de type incomplet

- **Erreur**: `invalid use of incomplete type` pour `PacketData` et `TCPReassembler`.
- **Cause**: Utilisation de classes déclarées (forward-declared) dans des contextes qui nécessitent leur définition complète.
- **Corrections**:
    - Ajout de `#include "tcp_reassembler.h"` dans `src/handlers/packet_handler.cpp`.
    - Réorganisation des includes dans `src/engine/worker_pool.h`.
    - Ajout de `#include "../engine/rule_engine.h"` dans `src/handlers/tcp_reassembler.cpp`.

## Erreur 7: Erreur de `const`-correctness

- **Erreur**: `binding reference of type ‘std::mutex&’ to ‘const std::mutex’ discards qualifiers`.
- **Cause**: Une méthode `const` (`GetStats`) tentait de verrouiller un mutex non-`const`.
- **Correction**: Le mutex `queue_mutex_` a été déclaré `mutable` dans `src/engine/worker_pool.h`.

## Erreur 8: Erreurs de déclaration/définition

- **Erreur**: `‘DispatchToWorkerOptimized’ was not declared in this scope` et `‘class TCPReassembler’ has no member named ‘ProcessPacketForHTTP’`.
- **Cause**: Membres de classe utilisés sans avoir été déclarés dans le fichier d'en-tête, ou coquilles.
- **Corrections**:
    - Ajout de la déclaration de `DispatchToWorkerOptimized` dans `src/engine/hybrid_engine.h`.
    - Remplacement de `ProcessPacketForHTTP` par `ProcessPacket` dans `src/engine/hybrid_engine.cpp`.

## Erreur 9: Erreur d'appel de méthode

- **Erreur**: `‘class RuleEngine’ has no member named ‘FilterPacketSequential’`.
- **Cause**: Appel d'une méthode d'une classe dérivée (`SequentialEngine`) sur un pointeur de la classe de base (`RuleEngine`).
- **Correction**: Remplacement de l'appel à `FilterPacketSequential` par `FilterPacket` (qui est virtuelle) dans `src/engine/worker_pool.cpp`.
