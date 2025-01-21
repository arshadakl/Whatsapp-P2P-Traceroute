import geoip2.database

# Download the MaxMind GeoLite2 database and provide its path
GEO_DB_PATH = "path/to/GeoLite2-City.mmdb"

def get_geo_info(ip):
    try:
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
    except Exception as e:
        print(f"[-] Error fetching geolocation for {ip}: {e}")
        return None
