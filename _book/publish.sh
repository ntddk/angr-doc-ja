cp _book/.git ./.git_tmp
gitbook build
cp ./.git_tmp _book/.git
cd _book/
git checkout gh-pages
git add --all .
git commit -m 'update'
git remote add origin git@github.com:ntddk/angr-doc-ja.git
git push origin -u gh-pages