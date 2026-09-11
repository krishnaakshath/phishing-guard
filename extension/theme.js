/**
 * Genuine sunrise/sunset-based light/dark theming - not a fixed clock
 * heuristic. Uses the NOAA approximate solar position algorithm, which is
 * accurate to within a minute or two for this purpose (deciding light vs
 * dark, not navigation-grade precision).
 *
 * Platform note: navigator.geolocation only exists in window/document
 * contexts (popup.html), not in the MV3 service worker - so this must run
 * from the popup, with the resulting coordinates cached so later opens
 * don't need to re-request location (the browser won't re-prompt for an
 * already-granted permission anyway, but caching avoids the round-trip).
 */

const LOCATION_CACHE_KEY = 'pgThemeLocation';
const LOCATION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // refresh once a day - a day's travel rarely changes sunrise/sunset enough to matter

/**
 * NOAA approximate sunrise/sunset calculation.
 * Returns { sunrise: Date, sunset: Date } in UTC, or a polar-day/night flag.
 */
export function computeSunTimes(date, lat, lon) {
    const rad = Math.PI / 180;
    const startOfYear = new Date(Date.UTC(date.getUTCFullYear(), 0, 0));
    const dayOfYear = Math.floor((date - startOfYear) / 86400000);

    const fractionalYear = (2 * Math.PI / 365) * (dayOfYear - 1 + (date.getUTCHours() - 12) / 24);

    const eqTime = 229.18 * (
        0.000075 + 0.001868 * Math.cos(fractionalYear) - 0.032077 * Math.sin(fractionalYear)
        - 0.014615 * Math.cos(2 * fractionalYear) - 0.040849 * Math.sin(2 * fractionalYear)
    );

    const decl = 0.006918
        - 0.399912 * Math.cos(fractionalYear) + 0.070257 * Math.sin(fractionalYear)
        - 0.006758 * Math.cos(2 * fractionalYear) + 0.000907 * Math.sin(2 * fractionalYear)
        - 0.002697 * Math.cos(3 * fractionalYear) + 0.00148 * Math.sin(3 * fractionalYear);

    // 90.833deg accounts for atmospheric refraction + the sun's apparent radius
    // (the standard civil definition of sunrise/sunset, not geometric horizon).
    const zenith = 90.833 * rad;
    const haArg = (Math.cos(zenith) / (Math.cos(lat * rad) * Math.cos(decl))) - Math.tan(lat * rad) * Math.tan(decl);

    if (haArg > 1) return { polarNight: true };
    if (haArg < -1) return { polarDay: true };

    const ha = Math.acos(haArg) / rad;
    const solarNoonMin = 720 - 4 * lon - eqTime; // minutes from UTC midnight
    const sunriseMin = solarNoonMin - ha * 4;
    const sunsetMin = solarNoonMin + ha * 4;

    const toUtcDate = (minutesFromMidnight) => {
        const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
        d.setUTCMinutes(minutesFromMidnight);
        return d;
    };

    return { sunrise: toUtcDate(sunriseMin), sunset: toUtcDate(sunsetMin) };
}

async function getCachedLocation(browserAPI) {
    try {
        const saved = await browserAPI.storage.local.get([LOCATION_CACHE_KEY]);
        const cached = saved[LOCATION_CACHE_KEY];
        if (cached && Date.now() - cached.fetchedAt < LOCATION_MAX_AGE_MS) {
            return cached;
        }
    } catch (e) {
        // fall through to a fresh request
    }
    return null;
}

function requestFreshLocation() {
    return new Promise((resolve) => {
        if (!navigator.geolocation) {
            resolve(null);
            return;
        }
        // Short timeout - this must never block the popup from being usable.
        // A denial, timeout, or unsupported browser all resolve to null and
        // the caller falls back to a clock-based heuristic.
        navigator.geolocation.getCurrentPosition(
            (pos) => resolve({ lat: pos.coords.latitude, lon: pos.coords.longitude, fetchedAt: Date.now() }),
            () => resolve(null),
            { timeout: 3000, maximumAge: LOCATION_MAX_AGE_MS }
        );
    });
}

/**
 * Determines whether it's currently daytime. Tries real sunrise/sunset at
 * the user's location; falls back to a plain 6am-6pm local-clock heuristic
 * if location is unavailable/denied - this is intentionally forgiving
 * rather than defaulting to always-dark or always-light.
 */
export async function isDaytimeNow(browserAPI) {
    let location = await getCachedLocation(browserAPI);

    if (!location) {
        location = await requestFreshLocation();
        if (location) {
            try {
                await browserAPI.storage.local.set({ [LOCATION_CACHE_KEY]: location });
            } catch (e) {
                // non-fatal - we still have the value for this call
            }
        }
    }

    if (!location) {
        const hour = new Date().getHours();
        return hour >= 6 && hour < 18;
    }

    const sunTimes = computeSunTimes(new Date(), location.lat, location.lon);
    if (sunTimes.polarDay) return true;
    if (sunTimes.polarNight) return false;

    const now = Date.now();
    return now >= sunTimes.sunrise.getTime() && now < sunTimes.sunset.getTime();
}

/** Applies the resolved theme as data-theme on <html>, matching the CSS in popup.css. */
export async function applyAutoTheme(browserAPI) {
    try {
        const daytime = await isDaytimeNow(browserAPI);
        document.documentElement.dataset.theme = daytime ? 'light' : 'dark';
    } catch (e) {
        // Never let a theming failure break the popup - dark is the
        // original/default look, so fall back to it silently.
        document.documentElement.dataset.theme = 'dark';
    }
}
