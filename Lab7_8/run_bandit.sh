
#!/bin/bash

REPO=$1
cd $REPO
git log --no-merges -n 100 --pretty=format:"%H" > commits.txt

mkdir -p bandit_reports

while read -r COMMIT; do
    git checkout $COMMIT
    source venv/bin/activate
    bandit -r . -f json -o "bandit_reports/${COMMIT}.json"
done < commits.txt

git checkout main  # Switch back to main branch
cd ..

