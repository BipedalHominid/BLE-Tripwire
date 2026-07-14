# F-Droid submission notes

This repo is structured to be F-Droid friendly (GPL-3.0, fastlane metadata,
no Google Play Services, no trackers, no proprietary SDKs). There are two
build-system realities you need to know about before submitting to fdroiddata.

## 1. libnode.so — the one real blocker

The app embeds a Node.js runtime via [nodejs-mobile](https://github.com/nodejs-mobile/nodejs-mobile).
For local development, `scripts/fetch-libnode.sh` downloads the **prebuilt**
`libnode.so` from the nodejs-mobile GitHub release. That is fine for building
and sideloading your own APK, and fine for publishing APKs on GitHub Releases
or your own repo.

**F-Droid's official repo will not accept a prebuilt binary blob.** Their build
server must compile everything from source. This is a solved problem — the
precedent is [Manyverse](https://gitlab.com/fdroid/fdroiddata/-/blob/master/metadata/se.manyver.yml),
which also ships nodejs-mobile and is on F-Droid — but it means the fdroiddata
recipe has to build nodejs-mobile from source (srclib) instead of running
`fetch-libnode.sh`. Expect this to be the bulk of the submission effort:

- srclib: `nodejs-mobile` pinned to the same tag as the vendored headers
  (`v18.20.4` — see `app/src/main/cpp/libnode/include/node/node_version.h`)
- prebuild step: compile libnode for `arm64-v8a` with the NDK, place the
  resulting `libnode.so` in `app/src/main/jniLibs/arm64-v8a/`
- then the normal gradle build

Until that recipe is written and accepted, the practical distribution paths
are: GitHub Releases, [IzzyOnDroid](https://apt.izzysoft.de/fdroid/) (which
accepts reproducibly-built APKs with prebuilt libs, and is where many apps
live while their fdroiddata recipe is in review), or your own F-Droid repo.
IzzyOnDroid is the recommended first stop — it typically takes days, not
months, and gets you an installable listing while the main-repo recipe is
worked out.

## 2. node_modules is committed on purpose

`app/src/main/assets/nodejs-project/node_modules/` (express and its
dependency tree, all plain-JS, all MIT/BSD-licensed) is committed so the
project builds with zero extra steps and so the shipped JS is exactly the
reviewed JS. F-Droid's scanner objects to binary blobs, not vendored JS
source. If a reviewer asks for it anyway, the alternative is a small gradle
task that runs `npm ci` in the assets dir before `mergeAssets` — the
`package-lock.json` is already present and pinned for exactly that.

## Anti-features: none

- No network access beyond the phone itself (server binds the phone; sensors
  connect over the phone's own hotspot; the app makes no outbound calls)
- No ads, no analytics, no tracking, no accounts
- No proprietary dependencies (androidx + nodejs-mobile + express only)
- All permissions are used and explained in the manifest comments
