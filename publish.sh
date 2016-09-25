cd _book/
git init
git branch -m gh-pages
git add --all .
git commit -m 'create gh-pages'
git remote add origin git@github.com:ntddk/angr-doc-ja.git
git push -f origin -u gh-pages