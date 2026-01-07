import pandas as pd
import re
from io import StringIO
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.svm import OneClassSVM  # Optional, but included for completeness
from statsmodels.tsa.arima.model import ARIMA

# Longer sample Apache access log (50 entries for better demonstration)
log_data = """
192.168.1.100 - - [01/Jan/2023:00:00:01 -0500] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:02 -0500] "GET /index.html HTTP/1.1" 200 567 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:00:03 -0500] "POST /login HTTP/1.1" 302 0 "http://example.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.100 - - [01/Jan/2023:00:00:04 -0500] "GET /dashboard HTTP/1.1" 200 890 "http://example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:05 -0500] "GET /css/style.css HTTP/1.1" 200 234 "http://example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
66.249.66.19 - - [01/Jan/2023:00:00:06 -0500] "GET /blog HTTP/1.1" 200 567 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.101 - - [01/Jan/2023:00:00:07 -0500] "GET /products HTTP/1.1" 200 678 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:00:08 -0500] "GET /wp-admin HTTP/1.1" 401 56 "-" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:00:09 -0500] "GET /api/data HTTP/1.1" 200 789 "http://example.com/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:10 -0500] "POST /api/users HTTP/1.1" 201 0 "http://example.com/api" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:00:11 -0500] "GET /products/1 HTTP/1.1" 200 890 "http://example.com/products" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.102 - - [01/Jan/2023:00:00:12 -0500] "GET /404 HTTP/1.1" 404 123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
66.249.66.19 - - [01/Jan/2023:00:00:13 -0500] "GET /robots.txt HTTP/1.1" 200 34 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.100 - - [01/Jan/2023:00:00:14 -0500] "GET /favicon.ico HTTP/1.1" 200 12 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:15 -0500] "HEAD / HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
198.51.100.5 - - [01/Jan/2023:00:00:16 -0500] "GET /admin/login HTTP/1.1" 200 678 "http://example.com/wp-admin" "curl/7.68.0"
192.168.1.101 - - [01/Jan/2023:00:00:17 -0500] "POST /login HTTP/1.1" 401 56 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
172.16.0.50 - - [01/Jan/2023:00:00:18 -0500] "GET /cart HTTP/1.1" 200 901 "http://example.com/products" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.100 - - [01/Jan/2023:00:00:19 -0500] "GET /blog/post1 HTTP/1.1" 200 567 "http://example.com/blog" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:20 -0500] "GET /about HTTP/1.1" 200 890 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
66.249.66.19 - - [01/Jan/2023:00:00:21 -0500] "GET /sitemap.xml HTTP/1.1" 200 567 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.102 - - [01/Jan/2023:00:00:22 -0500] "POST /contact HTTP/1.1" 200 0 "http://example.com/contact" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:00:23 -0500] "GET /wp-login.php HTTP/1.1" 404 123 "-" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:00:24 -0500] "GET /products HTTP/1.1" 200 678 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:25 -0500] "GET /js/main.js HTTP/1.1" 200 345 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:00:26 -0500] "POST /cart/add HTTP/1.1" 200 0 "http://example.com/cart" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.101 - - [01/Jan/2023:00:00:27 -0500] "GET /checkout HTTP/1.1" 200 123 "http://example.com/cart" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:00:28 -0500] "HEAD /admin HTTP/1.1" 401 0 "-" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:00:29 -0500] "GET /blog/post2 HTTP/1.1" 200 789 "http://example.com/blog" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:30 -0500] "GET /contact HTTP/1.1" 200 901 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
66.249.66.19 - - [01/Jan/2023:00:00:31 -0500] "GET /blog/post3 HTTP/1.1" 200 678 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.102 - - [01/Jan/2023:00:00:32 -0500] "GET /search?q=test HTTP/1.1" 200 890 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
172.16.0.50 - - [01/Jan/2023:00:00:33 -0500] "POST /checkout HTTP/1.1" 200 0 "http://example.com/checkout" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.100 - - [01/Jan/2023:00:00:34 -0500] "GET /profile HTTP/1.1" 200 901 "http://example.com/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:35 -0500] "PUT /profile HTTP/1.1" 200 0 "http://example.com/profile" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
198.51.100.5 - - [01/Jan/2023:00:00:36 -0500] "GET /test.php HTTP/1.1" 404 123 "-" "curl/7.68.0"
192.168.1.101 - - [01/Jan/2023:00:00:37 -0500] "GET /settings HTTP/1.1" 200 123 "http://example.com/profile" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
66.249.66.19 - - [01/Jan/2023:00:00:38 -0500] "GET /terms HTTP/1.1" 200 345 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.100 - - [01/Jan/2023:00:00:39 -0500] "POST /settings HTTP/1.1" 200 0 "http://example.com/settings" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:40 -0500] "GET /help HTTP/1.1" 200 234 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:00:41 -0500] "GET /order/123 HTTP/1.1" 200 234 "http://example.com/checkout" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.102 - - [01/Jan/2023:00:00:42 -0500] "GET /reviews HTTP/1.1" 200 345 "http://example.com/products" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:00:43 -0500] "POST /login?user=admin HTTP/1.1" 401 56 "http://example.com/" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:00:44 -0500] "GET /download/file.pdf HTTP/1.1" 200 789 "http://example.com/help" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:45 -0500] "GET /upload HTTP/1.1" 200 890 "http://example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
66.249.66.19 - - [01/Jan/2023:00:00:46 -0500] "GET /privacy HTTP/1.1" 200 456 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.101 - - [01/Jan/2023:00:00:47 -0500] "POST /upload HTTP/1.1" 200 0 "http://example.com/upload" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
172.16.0.50 - - [01/Jan/2023:00:00:48 -0500] "GET /cart HTTP/1.1" 200 901 "http://example.com/products" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.100 - - [01/Jan/2023:00:00:49 -0500] "GET /blog HTTP/1.1" 200 567 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:50 -0500] "GET /products/2 HTTP/1.1" 200 678 "http://example.com/products" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
198.51.100.5 - - [01/Jan/2023:00:00:51 -0500] "GET /config.bak HTTP/1.1" 404 123 "-" "curl/7.68.0"
192.168.1.102 - - [01/Jan/2023:00:00:52 -0500] "GET /about HTTP/1.1" 200 890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
66.249.66.19 - - [01/Jan/2023:00:00:53 -0500] "GET /feed.rss HTTP/1.1" 200 678 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.100 - - [01/Jan/2023:00:00:54 -0500] "POST /contact HTTP/1.1" 200 0 "http://example.com/contact" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:00:55 -0500] "GET /js/vendor.js HTTP/1.1" 200 345 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:00:56 -0500] "GET /products/3 HTTP/1.1" 200 789 "http://example.com/products" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.101 - - [01/Jan/2023:00:00:57 -0500] "GET /checkout HTTP/1.1" 200 123 "http://example.com/cart" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:00:58 -0500] "POST /login?user=root HTTP/1.1" 401 56 "http://example.com/" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:00:59 -0500] "GET /blog/post4 HTTP/1.1" 200 567 "http://example.com/blog" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:00 -0500] "GET /contact HTTP/1.1" 200 901 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
66.249.66.19 - - [01/Jan/2023:00:01:01 -0500] "GET /blog/post5 HTTP/1.1" 200 678 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.102 - - [01/Jan/2023:00:01:02 -0500] "GET /search?q=sqlmap HTTP/1.1" 200 890 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
172.16.0.50 - - [01/Jan/2023:00:01:03 -0500] "POST /checkout HTTP/1.1" 200 0 "http://example.com/checkout" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.100 - - [01/Jan/2023:00:01:04 -0500] "GET /profile HTTP/1.1" 200 901 "http://example.com/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:05 -0500] "PUT /profile HTTP/1.1" 200 0 "http://example.com/profile" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
198.51.100.5 - - [01/Jan/2023:00:01:06 -0500] "GET /backup.sql HTTP/1.1" 404 123 "-" "curl/7.68.0"
192.168.1.101 - - [01/Jan/2023:00:01:07 -0500] "GET /settings HTTP/1.1" 200 123 "http://example.com/profile" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
66.249.66.19 - - [01/Jan/2023:00:01:08 -0500] "GET /terms HTTP/1.1" 200 345 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.100 - - [01/Jan/2023:00:01:09 -0500] "POST /settings HTTP/1.1" 200 0 "http://example.com/settings" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:10 -0500] "GET /help HTTP/1.1" 200 234 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:01:11 -0500] "GET /order/123 HTTP/1.1" 200 234 "http://example.com/checkout" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.102 - - [01/Jan/2023:00:01:12 -0500] "GET /reviews HTTP/1.1" 200 345 "http://example.com/products" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:01:13 -0500] "POST /login?user=admin HTTP/1.1" 401 56 "http://example.com/" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:01:14 -0500] "GET /download/file.pdf HTTP/1.1" 200 789 "http://example.com/help" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:15 -0500] "GET /upload HTTP/1.1" 200 890 "http://example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
66.249.66.19 - - [01/Jan/2023:00:01:16 -0500] "GET /privacy HTTP/1.1" 200 456 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.101 - - [01/Jan/2023:00:01:17 -0500] "POST /upload HTTP/1.1" 200 0 "http://example.com/upload" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
172.16.0.50 - - [01/Jan/2023:00:01:18 -0500] "GET /cart HTTP/1.1" 200 901 "http://example.com/products" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.100 - - [01/Jan/2023:00:01:19 -0500] "GET /blog HTTP/1.1" 200 567 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:20 -0500] "GET /products/2 HTTP/1.1" 200 678 "http://example.com/products" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
198.51.100.5 - - [01/Jan/2023:00:01:21 -0500] "GET /config.bak HTTP/1.1" 404 123 "-" "curl/7.68.0"
192.168.1.102 - - [01/Jan/2023:00:01:22 -0500] "GET /about HTTP/1.1" 200 890 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
66.249.66.19 - - [01/Jan/2023:00:01:23 -0500] "GET /feed.rss HTTP/1.1" 200 678 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.168.1.100 - - [01/Jan/2023:00:01:24 -0500] "POST /contact HTTP/1.1" 200 0 "http://example.com/contact" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:25 -0500] "GET /js/vendor.js HTTP/1.1" 200 345 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
172.16.0.50 - - [01/Jan/2023:00:01:26 -0500] "GET /products/3 HTTP/1.1" 200 789 "http://example.com/products" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
192.168.1.101 - - [01/Jan/2023:00:01:27 -0500] "GET /checkout HTTP/1.1" 200 123 "http://example.com/cart" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
198.51.100.5 - - [01/Jan/2023:00:01:28 -0500] "POST /login?user=root HTTP/1.1" 401 56 "http://example.com/" "curl/7.68.0"
192.168.1.100 - - [01/Jan/2023:00:01:29 -0500] "GET /blog/post4 HTTP/1.1" 200 567 "http://example.com/blog" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
203.0.113.10 - - [01/Jan/2023:00:01:30 -0500] "GET /contact HTTP/1.1" 200 901 "http://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/14.1.2"
"""

# Regex pattern for Combined Log Format
log_pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "([^"]*)" "([^"]*)"'

# Parse logs into DataFrame
parsed_logs = []
for line in StringIO(log_data):
    match = re.match(log_pattern, line.strip())
    if match:
        parsed_logs.append({
            'ip': match.group(1),
            'timestamp': pd.to_datetime(match.group(2), format='%d/%b/%Y:%H:%M:%S %z'),
            'method': match.group(3),
            'endpoint': match.group(4),
            'status': int(match.group(5)),
            'bytes_sent': int(match.group(6)),
            'referrer': match.group(7),
            'user_agent': match.group(8)
        })

df = pd.DataFrame(parsed_logs)
print("Parsed Log DataFrame (first 5 rows):")
print(df.head())

# Feature engineering: Add request count per IP
ip_counts = df.groupby('ip').size().reset_index(name='request_count')
df = df.merge(ip_counts, on='ip')

# Common preprocessor for categorical features
features = ['method', 'status', 'bytes_sent', 'request_count']
categorical_features = ['method', 'status']
preprocessor = ColumnTransformer(
    [('onehot', OneHotEncoder(handle_unknown='ignore'), categorical_features)],
    remainder='passthrough'
)

# 1. Statistical Method
print("\n1. Statistical Baseline:")
ip_stats = df.groupby('ip').agg(
    request_count=('request_count', 'first'),  # Since it's constant per IP
    avg_bytes=('bytes_sent', 'mean'),
    std_bytes=('bytes_sent', 'std')
).fillna(0)

mean_requests = ip_stats['request_count'].mean()
std_requests = ip_stats['request_count'].std()
mean_bytes = df['bytes_sent'].mean()
status_dist = df['status'].value_counts(normalize=True)
request_threshold = mean_requests + 3 * std_requests

print(f"Mean requests per IP: {mean_requests:.2f}, Std: {std_requests:.2f}, Threshold: {request_threshold:.2f}")
print(f"Status distribution:\n{status_dist}")
print(f"Mean bytes sent: {mean_bytes:.2f}")
anomalous_ips_stat = ip_stats[ip_stats['request_count'] > request_threshold].index.tolist()
print(f"Anomalous IPs (statistical): {anomalous_ips_stat}")

# 2. Rule-Based Method
print("\n2. Rule-Based Baseline:")
allowed_methods = ['GET', 'POST']
allowed_status = [200, 201, 204, 302]
malicious_patterns = ['sqlmap', 'nikto', 'admin']  # Example suspicious strings in endpoint or agent

df['rule_anomalous'] = False
df.loc[~df['method'].isin(allowed_methods), 'rule_anomalous'] = True
df.loc[~df['status'].isin(allowed_status), 'rule_anomalous'] = True
for pattern in malicious_patterns:
    df.loc[df['endpoint'].str.contains(pattern, case=False, na=False) |
           df['user_agent'].str.contains(pattern, case=False, na=False), 'rule_anomalous'] = True

normal_proportion = 1 - (df['rule_anomalous'].sum() / len(df))
print(f"Baseline normal proportion: {normal_proportion:.2f}")
print("Anomalous logs (rule-based):")
print(df[df['rule_anomalous']][['timestamp', 'ip', 'method', 'endpoint', 'status']])

# 3. Machine Learning Method (Isolation Forest)
print("\n3. Machine Learning Baseline (Isolation Forest):")
X_ml = preprocessor.fit_transform(df[features])
model_if = IsolationForest(contamination=0.1, random_state=42)
model_if.fit(X_ml)
df['ml_anomaly_score'] = model_if.decision_function(X_ml)
df['ml_is_anomalous'] = model_if.predict(X_ml) == -1

print("Anomaly scores and flags (lower score = more anomalous):")
print(df[['timestamp', 'ip', 'endpoint', 'ml_anomaly_score', 'ml_is_anomalous']].head(10))
print(f"Number of anomalies: {df['ml_is_anomalous'].sum()}")

# Optional: One-Class SVM for comparison
X_scaled = StandardScaler().fit_transform(X_ml.toarray() if hasattr(X_ml, 'toarray') else X_ml)
model_svm = OneClassSVM(kernel='rbf', nu=0.1)
model_svm.fit(X_scaled)
df['svm_anomaly_score'] = model_svm.decision_function(X_scaled)
df['svm_is_anomalous'] = model_svm.predict(X_scaled) == -1
print("One-Class SVM anomalies:")
print(df[df['svm_is_anomalous']][['timestamp', 'ip', 'endpoint']])

# 4. Time-Series Method (ARIMA for request rates)
print("\n4. Time-Series Baseline (ARIMA):")
df.set_index('timestamp', inplace=True)
ts = df.resample('s').size().fillna(0)  # Requests per second (adjust resolution for larger logs)
model_arima = ARIMA(ts, order=(1,1,1))  # Simple order; tune with ACF/PACF for real data
model_fit = model_arima.fit()
forecast = model_fit.forecast(steps=10)
residuals = model_fit.resid
threshold = residuals.std() * 3
anomalies_ts = ts[abs(residuals) > threshold]

print(f"Baseline forecast for next 10 seconds:\n{forecast}")
print(f"Anomalies based on residuals:\n{anomalies_ts}")

# 5. Hybrid Method (Statistical + ML)
print("\n5. Hybrid Baseline (Statistical + ML):")
# Step 1: Statistical filter (high request IPs)
high_request_ips = ip_stats[ip_stats['request_count'] > request_threshold].index

# Step 2: Apply ML on filtered data
df_high = df[df['ip'].isin(high_request_ips)]
if not df_high.empty:
    X_high = preprocessor.transform(df_high[features])
    model_if.fit(X_high)
    df_high['hybrid_anomalous'] = model_if.predict(X_high) == -1
    print("Hybrid anomalies:")
    print(df_high[df_high['hybrid_anomalous']][['timestamp', 'ip', 'endpoint']])
else:
    print("No high-request IPs for hybrid refinement.")

# Reset index for any further use
# df.reset_index(inplace=True)

# For your project: Export anomalies to CSV for LLM input
# df[df['ml_is_anomalous']].to_csv('anomalies.csv', index=False)