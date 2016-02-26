# Build
```
npm install -g cordova;
npm install;

cd node_modules/sjcl && ./configure --with-sha512 --with-hmac --with-pbkdf2 --with-bitArray && make && cd ../..;

./node_modules/.bin/browserify www/index.js -o www/build.js;
```

# Run in Browser
```
./node_modules/serve/bin/serve ./www
```

# Run Cordova IOS
```
cordova run ios
```

# Run Cordova Android
```
cordova run android
```

# Node v0.10.36
```
sjcl.misc.pbkdf2 4759 = 475.9
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 471 = 47.1
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Node v0.12.4
```
sjcl.misc.pbkdf2 741 = 74.1
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 44 = 4.4
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Chromium v41.0.22272.63 beta (Ubuntu)
```
sjcl.misc.pbkdf2 786 = 78.7
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 8109 = 810.9
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Firefox (Ubuntu)
```
sjcl.misc.pbkdf2 11027 = 1102.8
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 8109 = 810.9
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Android Stock Browser (Android 5.0 Emulator)
```
sjcl.misc.pbkdf2 11027 = 1102.8
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
TOOOOOOOOOOOOO SLOW
```

# Chrome 32.0.1700.99 (Android 4.4.3 Nexus 4)
```
sjcl.misc.pbkdf2 524 = 524
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 3938 = 3938
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Android Stock Browser (CyanogenMod 11 (~Android 4.4.3) Nexus 5)
```
sjcl.misc.pbkdf2 1975 = 197.5
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 62854 = 6285.4
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Chrome 42.0.2311.111 (CyanogenMod 11 (~Android 4.4.3) Nexus 5)
```
sjcl.misc.pbkdf2 2007 = 200.7
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 38350 = 3835.0
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Cordova IOS 3.8.0 (iPhone 6 Emulator iOS 8.3)
```
sjcl.misc.pbkdf2 6514 = 651.4
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 12215 = 1221.5
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Cordova IOS 3.8.0 (iPhone 6 iOS 8.3)
```
sjcl.misc.pbkdf2 9941 = 994.1
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 88831 = 8883.1
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Cordova IOS 3.8.0 + com.telerik.plugins.wkwebview (iPhone 6 iOS 8.3)
```
cordova plugin add com.telerik.plugins.wkwebview
```

```
sjcl.misc.pbkdf2 5245 = 1049
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 3797 = 759.4
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

# Safari (iPhone 6 iOS 8.3)
```
sjcl.misc.pbkdf2 1061 = 1061
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
pbkdf2.pbkdf2Sync 976 = 976
edb67c00b040d72d91a44840995e5e12ca2ea37937e16a8cfa77978fdf79f0596b0d33bedcfbdfefbed5ea61badf54815d1093e4a03db305000fd94024e50712
```

