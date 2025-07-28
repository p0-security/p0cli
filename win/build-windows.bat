:: See https://nodejs.org/docs/latest-v20.x/api/single-executable-applications.html for more information.

echo Starting Node-SEA build...

node --experimental-sea-config sea-config.json
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%

echo Copying node binary...

node -e "require('fs').copyFileSync(process.execPath, '.\\build\\sea\\p0.exe')"
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%

echo Removing existing signature...

signtool remove /s .\build\sea\p0.exe
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%

echo Running postject...

npx postject .\build\sea\p0.exe NODE_SEA_BLOB .\build\sea\p0.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%

echo Build completed successfully.
exit /b 0