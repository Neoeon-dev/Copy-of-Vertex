# GeoLite2 Database Setup

MaxMind GeoLite2 databases are required for live IP geolocation.

## Download Instructions

1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
2. Download these databases:
   - GeoLite2-City.mmdb
   - GeoLite2-ASN.mmdb
3. Place them in this directory (`backend/data/geoip/`)

## Environment Variable

You can also set `GEOIP_DB_DIR` to point to a different directory.

## Without Databases

The system works without GeoLite2 databases — IP intelligence will return
"warnings" indicating geolocation data is unavailable. All other analysis
features remain fully functional.
