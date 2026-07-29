#!/usr/bin/env bash
# Lance les tests d'un exercice, ou de tous.
#
#   bash learning/exercices/verifier.sh            # tous les exercices
#   bash learning/exercices/verifier.sh ex3        # un seul (prefixe suffisant)
#
# Aucune dependance : uniquement unittest de la bibliotheque standard.

set -uo pipefail
cd "$(dirname "$0")"

filtre="${1:-}"
total_ok=0 total_ko=0 total_todo=0

for d in ex*/; do
  nom="${d%/}"
  [[ -n "$filtre" && "$nom" != "$filtre"* ]] && continue

  sortie=$(cd "$nom" && python3 -m unittest discover -q 2>&1)
  code=$?

  if grep -q "NotImplementedError" <<<"$sortie"; then
    etat=$'\033[33mA FAIRE\033[0m'
    ((total_todo++))
  elif [[ $code -eq 0 ]]; then
    etat=$'\033[32mOK\033[0m'
    ((total_ok++))
  else
    etat=$'\033[31mECHEC\033[0m'
    ((total_ko++))
  fi

  stats=$(grep -oE "Ran [0-9]+ test" <<<"$sortie" | head -1)
  fails=$(grep -cE "^(FAIL|ERROR):" <<<"$sortie")
  printf '%-24s %-18b %s' "$nom" "$etat" "${stats:-}"
  [[ $fails -gt 0 ]] && printf '  (%s en echec)' "$fails"
  printf '\n'

  if [[ -n "$filtre" ]]; then
    echo
    echo "$sortie"
  fi
done

echo
printf 'Termine : %d OK, %d en echec, %d pas encore commences.\n' \
  "$total_ok" "$total_ko" "$total_todo"
[[ -z "$filtre" ]] && echo "Detail d'un exercice : bash learning/exercices/verifier.sh ex1"
exit 0
