/**
 * Same NOAA approximate sunrise/sunset calculation as the extension's
 * theme.js (kept as a separate copy since the dashboard and extension are
 * different deployable apps with no shared build step - see that file for
 * the derivation notes). Falls back to a 6am-6pm local-clock heuristic
 * when geolocation is unavailable/denied.
 */

const LOCATION_CACHE_KEY = 'pg_theme_location'
const LOCATION_MAX_AGE_MS = 24 * 60 * 60 * 1000

export function computeSunTimes(date, lat, lon) {
  const rad = Math.PI / 180
  const startOfYear = new Date(Date.UTC(date.getUTCFullYear(), 0, 0))
  const dayOfYear = Math.floor((date - startOfYear) / 86400000)

  const fractionalYear = (2 * Math.PI / 365) * (dayOfYear - 1 + (date.getUTCHours() - 12) / 24)

  const eqTime = 229.18 * (
    0.000075 + 0.001868 * Math.cos(fractionalYear) - 0.032077 * Math.sin(fractionalYear)
    - 0.014615 * Math.cos(2 * fractionalYear) - 0.040849 * Math.sin(2 * fractionalYear)
  )

  const decl = 0.006918
    - 0.399912 * Math.cos(fractionalYear) + 0.070257 * Math.sin(fractionalYear)
    - 0.006758 * Math.cos(2 * fractionalYear) + 0.000907 * Math.sin(2 * fractionalYear)
    - 0.002697 * Math.cos(3 * fractionalYear) + 0.00148 * Math.sin(3 * fractionalYear)

  const zenith = 90.833 * rad
  const haArg = (Math.cos(zenith) / (Math.cos(lat * rad) * Math.cos(decl))) - Math.tan(lat * rad) * Math.tan(decl)

  if (haArg > 1) return { polarNight: true }
  if (haArg < -1) return { polarDay: true }

  const ha = Math.acos(haArg) / rad
  const solarNoonMin = 720 - 4 * lon - eqTime
  const sunriseMin = solarNoonMin - ha * 4
  const sunsetMin = solarNoonMin + ha * 4

  const toUtcDate = (minutesFromMidnight) => {
    const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()))
    d.setUTCMinutes(minutesFromMidnight)
    return d
  }

  return { sunrise: toUtcDate(sunriseMin), sunset: toUtcDate(sunsetMin) }
}

function getCachedLocation() {
  try {
    const raw = localStorage.getItem(LOCATION_CACHE_KEY)
    if (!raw) return null
    const cached = JSON.parse(raw)
    if (Date.now() - cached.fetchedAt < LOCATION_MAX_AGE_MS) return cached
  } catch {
    // ignore malformed cache
  }
  return null
}

function requestFreshLocation() {
  return new Promise((resolve) => {
    if (!navigator.geolocation) {
      resolve(null)
      return
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: pos.coords.latitude, lon: pos.coords.longitude, fetchedAt: Date.now() }),
      () => resolve(null),
      { timeout: 3000, maximumAge: LOCATION_MAX_AGE_MS }
    )
  })
}

/** Resolves to true if it's currently daytime - real sunrise/sunset when
 * location is available, a 6am-6pm clock heuristic otherwise. */
export async function isDaytimeNow() {
  let location = getCachedLocation()

  if (!location) {
    location = await requestFreshLocation()
    if (location) {
      try {
        localStorage.setItem(LOCATION_CACHE_KEY, JSON.stringify(location))
      } catch {
        // non-fatal
      }
    }
  }

  if (!location) {
    const hour = new Date().getHours()
    return hour >= 6 && hour < 18
  }

  const sunTimes = computeSunTimes(new Date(), location.lat, location.lon)
  if (sunTimes.polarDay) return true
  if (sunTimes.polarNight) return false

  const now = Date.now()
  return now >= sunTimes.sunrise.getTime() && now < sunTimes.sunset.getTime()
}
