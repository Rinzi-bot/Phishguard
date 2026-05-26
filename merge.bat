@echo off
REM Merge script for PhishGuard topic branch
REM This script merges agents/pdf-file-naming-structure-update into main

setlocal enabledelayedexpansion

REM Change to main worktree
cd /d "C:\xampp\htdocs\phishguard"
if !errorlevel! neq 0 (
    echo Error: Cannot change to main worktree directory
    exit /b 1
)

echo.
echo === Merge Status ===
echo Current directory: %cd%
git status --short
echo.

echo === Checking for uncommitted changes in main branch ===
for /f "usebackq" %%A in (`git status --porcelain`) do (
    echo Uncommitted changes found:
    echo %%A
    echo Error: Main worktree has uncommitted changes. Aborting merge.
    exit /b 1
)

echo Main worktree is clean. Proceeding with merge.
echo.

echo === Merging agents/pdf-file-naming-structure-update into main ===
git merge agents/pdf-file-naming-structure-update
if !errorlevel! neq 0 (
    echo Error: Merge failed with exit code !errorlevel!
    echo.
    echo === Conflicted files ===
    git diff --name-only --diff-filter=U
    exit /b 1
)

echo.
echo === Merge completed successfully ===
git log --oneline -3
echo.
echo === Verifying merge ===
git merge-base --is-ancestor agents/pdf-file-naming-structure-update HEAD
if !errorlevel! equ 0 (
    echo SUCCESS: Topic branch is ancestor of HEAD (all commits merged)
) else (
    echo WARNING: Topic branch verification failed
    exit /b 1
)

echo.
echo === Final status ===
git status --short

endlocal
exit /b 0
