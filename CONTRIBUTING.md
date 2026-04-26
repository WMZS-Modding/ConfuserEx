# How to contribute
1. First, you need the `.NET Framework 3.5` installed on your Windows
2. Fork the repository and clone to your computer
3. Clone `dnlib`
4. Make your changes
5. Run `Build.cmd`
6. If `NuGet.exe` fails, run the command to restore it:

```bash
powershell -Command "Invoke-WebRequest https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile NuGet.exe"
```

7. Test the built ConfuserEx
8. If success, push your change and then create pull request