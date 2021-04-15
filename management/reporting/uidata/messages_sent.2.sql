--
-- returns count of sent messages delivered in each 'bin'/delivery
-- service combination. the bin is the connection time rounded (as
-- defined by {timefmt})
--
SELECT
  strftime('{timefmt}',
    :start_unixepoch + cast((strftime('%s',connect_time) - :start_unixepoch) / (60 * :binsize) as int) * (60 * :binsize),
    'unixepoch'
  ) AS `bin`,
  mta_delivery.service AS `delivery_service`,
  count(*) AS `delivery_count`
FROM mta_accept
JOIN mta_connection ON mta_connection.mta_conn_id = mta_accept.mta_conn_id
JOIN mta_delivery ON mta_delivery.mta_accept_id = mta_accept.mta_accept_id
WHERE
  (mta_connection.service = 'submission' OR mta_connection.service = 'pickup') AND
  connect_time >= :start_date AND
  connect_time < :end_date
GROUP BY bin, mta_delivery.service
ORDER BY connect_time
