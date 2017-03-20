# -*- coding: utf-8 -*-
from __future__ import absolute_import

import base64
import hashlib
import hmac
import re
from time import gmtime, strftime

from requests import request
from requests.exceptions import HTTPError

from . import utils

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote
try:
    from xml.etree.ElementTree import ParseError as XMLError
except ImportError:
    from xml.parsers.expat import ExpatError as XMLError


__all__ = [
    'Feeds',
    'Inventory',
    'MWSError',
    'Reports',
    'Orders',
    'Products',
    'Recommendations',
    'Sellers',
    'InboundShipments'
]

# See https://images-na.ssl-images-amazon.com/images/G/01/mwsportal/doc/en_US/bde/MWSDeveloperGuide._V357736853_.pdf page 8
# for a list of the end points and marketplace IDs

MARKETPLACES = {
    "CA" : "https://mws.amazonservices.ca", #A2EUQ1WTGCTBG2
    "US" : "https://mws.amazonservices.com", #ATVPDKIKX0DER",
    "DE" : "https://mws-eu.amazonservices.com", #A1PA6795UKMFR9
    "ES" : "https://mws-eu.amazonservices.com", #A1RKKUPIHCS9HS
    "FR" : "https://mws-eu.amazonservices.com", #A13V1IB3VIYZZH
    "IN" : "https://mws.amazonservices.in", #A21TJRUUN4KGV
    "IT" : "https://mws-eu.amazonservices.com", #APJ6JRA9NG5V4
    "UK" : "https://mws-eu.amazonservices.com", #A1F83G8C2ARO7P
    "JP" : "https://mws.amazonservices.jp", #A1VC38T7YXB528
    "CN" : "https://mws.amazonservices.com.cn", #AAHKV2X7AFYLW
    "MX" : "https://mws.amazonservices.com.mx", #A1AM78C64UM0Y8    
}


class MWSError(Exception):
    """
    Main MWS Exception class

    """
    # Allows quick access to the response object.
    # Do not rely on this attribute, always check if its not None.
    response = None


def calc_md5(string):
    """
    Calculates the MD5 encryption for the given string

    :param string:
    :return:
    """
    md = hashlib.md5()
    md.update(string)
    return base64.encodebytes(md.digest()).strip('\n')


def remove_empty(d):
    """
    Helper function that removes all keys from a dictionary (d), that have an empty value.

    :param d: dict
    :return: dict
    """
    for key in set(d.keys()):
        if not d[key]:
            del d[key]
    return d


def remove_namespace(xml):
    """
    Removes the Namespace from XML response

    :param xml:
    :return:
    """
    regex = re.compile(' xmlns(:ns2)?="[^"]+"|(ns2:)|(xml:)')
    return regex.sub('', xml)


class DictWrapper(object):
    def __init__(self, xml, rootkey=None):
        """

        :param xml:
        :param rootkey:
        """
        self.original = xml
        self._rootkey = rootkey
        self._mydict = utils.xml2dict().fromstring(remove_namespace(xml))
        self._response_dict = self._mydict.get(list(self._mydict.keys())[0],
                                               self._mydict)

    @property
    def parsed(self):
        """

        :return:
        """
        if self._rootkey:
            return self._response_dict.get(self._rootkey)
        else:
            return self._response_dict


class DataWrapper(object):
    """
        Text wrapper in charge of validating the hash sent by Amazon.
    """
    def __init__(self, data, header):
        """

        :param data:
        :param header:
        """
        self.original = data
        if 'content-md5' in header:
            hash_ = calc_md5(self.original)
            if header['content-md5'] != hash_:
                raise MWSError("Wrong Contentlength, maybe amazon error...")

    @property
    def parsed(self):
        """

        :return:
        """
        return self.original


class MWS(object):
    """ Base Amazon API class """

    # This is used to post/get to the different uris used by amazon per api
    # ie. /Orders/2011-01-01
    # All subclasses must define their own URI only if needed
    URI = "/"

    # The API version varies in most amazon APIs
    VERSION = "2009-01-01"

    # There seem to be some xml namespace issues. therefore every api subclass
    # is recommended to define its namespace, so that it can be referenced
    # like so AmazonAPISubclass.NS.
    # For more information see http://stackoverflow.com/a/8719461/389453
    NS = ''

    # Some APIs are available only to either a "Merchant" or "Seller"
    # the type of account needs to be sent in every call to the amazon MWS.
    # This constant defines the exact name of the parameter Amazon expects
    # for the specific API being used.
    # All subclasses need to define this if they require another account type
    # like "Merchant" in which case you define it like so.
    # ACCOUNT_TYPE = "Merchant"
    # Which is the name of the parameter for that specific account type.
    ACCOUNT_TYPE = "SellerId"

    def __init__(self, access_key, secret_key, account_id, region='US', domain='', uri="", version="", auth_token=""):
        """
        Initialize the MWS object.

        :param access_key:
        :param secret_key:
        :param account_id:
        :param region:
        :param domain:
        :param uri:
        :param version:
        :param auth_token:
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.account_id = account_id
        self.auth_token = auth_token
        self.version = version or self.VERSION
        self.uri = uri or self.URI

        if domain:
            self.domain = domain
        elif region in MARKETPLACES:
            self.domain = MARKETPLACES[region]
        else:
            error_msg = "Incorrect region supplied ('%(region)s'). Must be one of the following: %(marketplaces)s" % {
                "marketplaces" : ', '.join(MARKETPLACES.keys()),
                "region" : region,
            }
            raise MWSError(error_msg)

    def make_request(self, extra_data, method="GET", **kwargs):
        """
        Make request to Amazon MWS API.

        1. Removes Blanks from url
        2. Generate Signature
        3. Submit Request
        4. Process Response

        :param extra_data:
        :param method:
        :param kwargs:
        :return:
        """

        # Remove all keys with an empty value
        extra_data = remove_empty(extra_data)

        params = {
            'AWSAccessKeyId': self.access_key,
            self.ACCOUNT_TYPE: self.account_id,
            'SignatureVersion': '2',
            'Timestamp': self.get_timestamp(),
            'Version': self.version,
            'SignatureMethod': 'HmacSHA256',
        }
        if self.auth_token:
            params['MWSAuthToken'] = self.auth_token
        params.update(extra_data)
        request_description = '&'.join(['%s=%s' % (k, quote(params[k], safe='-_.~')) for k in sorted(params)])
        signature = self.calc_signature(method, request_description)
        url = '%s%s?%s&Signature=%s' % (self.domain, self.uri, request_description, quote(signature))
        headers = {'User-Agent': 'python-amazon-mws/0.0.1 (Language=Python)'}
        headers.update(kwargs.get('extra_headers', {}))

        try:
            # Some might wonder as to why i don't pass the params dict as the params argument to request.
            # My answer is, here i have to get the url parsed string of params in order to sign it, so
            # if i pass the params dict as params to request, request will repeat that step because it will need
            # to convert the dict to a url parsed string, so why do it twice if i can just pass the full url :).
            response = request(method, url, data=kwargs.get('body', ''), headers=headers)
            response.raise_for_status()
            # When retrieving data from the response object,
            # be aware that response.content returns the content in bytes while response.text calls
            # response.content and converts it to unicode.

            data = response.content
            # I do not check the headers to decide which content structure to server simply because sometimes
            # Amazon's MWS API returns XML error responses with "text/plain" as the Content-Type.
            try:
                parsed_response = DictWrapper(data, extra_data.get("Action") + "Result")
            except TypeError:  # raised when using Python 3 and trying to remove_namespace()
                parsed_response = DictWrapper(response.text, extra_data.get("Action") + "Result")
            except XMLError:
                parsed_response = DataWrapper(data, response.headers)

        except HTTPError as e:
            error = MWSError(str(e.response.text))
            error.response = e.response
            raise error

        # Store the response object in the parsed_response for quick access
        parsed_response.response = response
        return parsed_response

    def get_service_status(self):
        """
        Returns a GREEN, GREEN_I, YELLOW or RED status.
        Depending on the status/availability of the API its being called from.

        :return: Status of API service
        """

        return self.make_request(extra_data=dict(Action='GetServiceStatus'))

    def calc_signature(self, method, request_description):
        """
        Calculate MWS signature to interface with Amazon

        :param method: (str)
        :param request_description: (str)
        :return: Signature String
        """

        sig_data = '\n'.join([
            method,
            self.domain.replace('https://', '').lower(),
            self.uri,
            request_description
        ])
        return base64.b64encode(hmac.new(self.secret_key.encode(), sig_data.encode(), hashlib.sha256).digest())

    def get_timestamp(self):
        """
        Returns the current timestamp in proper format.

        :return:
        """
        return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())

    def enumerate_dict(self, param,  dic):
        """
        Builds a dictionary of an enumerated parameter.
        Takes any iterable and returns a dictionary recursively

        :param param:
        :param dic:
        :return:
        """

        params = {}
        if dic is not None:
            if not param.endswith('.'):
                param = "%s." % param
            for key, value in dic.items():
                if isinstance(value, list):
                    for sub_key, sub_value in self.enumerate_list(param=key, values=value).items():
                        params['%s%s' % (key, sub_key)] = sub_value
                elif isinstance(value, dict):
                    for sub_key, sub_value in self.enumerate_dict(param=key, dic=value).items():
                        params['%s%s' % (key, sub_key)] = sub_value
                else:
                    params['%s%s' % (param, key)] = value
        return params

    def enumerate_list(self, param, values):
        """
        Builds a dictionary of an enumerated parameter.
        Takes any iterable and returns a dictionary.
        ie. enumerate_list('MarketplaceIdList.Id', (123, 345, 4343))
            returns
            {
                MarketplaceIdList.Id.1: 123,
                MarketplaceIdList.Id.2: 345,
                MarketplaceIdList.Id.3: 4343
            }

        :param param:
        :param values:
        :return:
        """

        params = {}
        if values is not None:
            if not param.endswith('.'):
                param = "%s." % param
            for num, value in enumerate(values):
                if isinstance(value, list):
                    for sub_key, sub_value in self.enumerate_dict(num, dic=values).items():
                        params['%s%d' % (param, (num + 1))]
                elif isinstance(value, dict):
                    for sub_key, sub_value in self.enumerate_dict(num, dic=values).items():
                        params['%s%d' % (param, (num + 1))]
                else:
                    params['%s%d' % (param, (num + 1))] = value
        return params


class Feeds(MWS):
    """ Amazon MWS Feeds API """

    ACCOUNT_TYPE = "Merchant"

    def submit_feed(self, feed, feed_type, marketplaceids=None,
                    content_type="text/xml", purge='false'):
        """
        Uploads a feed ( xml or .tsv ) to the seller's inventory.
        Can be used for creating/updating products on Amazon.

        :param feed:
        :param feed_type:
        :param marketplaceids:
        :param content_type:
        :param purge:
        :return:
        """
        data = dict(Action='SubmitFeed',
                    FeedType=feed_type,
                    PurgeAndReplace=purge)
        data.update(self.enumerate_list('MarketplaceIdList.Id.', marketplaceids))
        md = calc_md5(feed)
        return self.make_request(data, method="POST", body=feed,
                                 extra_headers={'Content-MD5': md, 'Content-Type': content_type})

    def get_feed_submission_list(self, feedids=None, max_count=None, feedtypes=None,
                                 processingstatuses=None, fromdate=None, todate=None):
        """
        Returns a list of all feed submissions submitted in the previous 90 days.
        That match the query parameters.

        :param feedids:
        :param max_count:
        :param feedtypes:
        :param processingstatuses:
        :param fromdate:
        :param todate:
        :return:
        """

        data = dict(Action='GetFeedSubmissionList',
                    MaxCount=max_count,
                    SubmittedFromDate=fromdate,
                    SubmittedToDate=todate,)
        data.update(self.enumerate_list('FeedSubmissionIdList.Id', feedids))
        data.update(self.enumerate_list('FeedTypeList.Type.', feedtypes))
        data.update(self.enumerate_list('FeedProcessingStatusList.Status.', processingstatuses))
        return self.make_request(data)

    def get_submission_list_by_next_token(self, token):
        """

        :param token:
        :return:
        """
        data = dict(Action='GetFeedSubmissionListByNextToken', NextToken=token)
        return self.make_request(data)

    def get_feed_submission_count(self, feedtypes=None, processingstatuses=None, fromdate=None, todate=None):
        """

        :param feedtypes:
        :param processingstatuses:
        :param fromdate:
        :param todate:
        :return:
        """
        data = dict(Action='GetFeedSubmissionCount',
                    SubmittedFromDate=fromdate,
                    SubmittedToDate=todate)
        data.update(self.enumerate_list('FeedTypeList.Type.', feedtypes))
        data.update(self.enumerate_list('FeedProcessingStatusList.Status.', processingstatuses))
        return self.make_request(data)

    def cancel_feed_submissions(self, feedids=None, feedtypes=None, fromdate=None, todate=None):
        """

        :param feedids:
        :param feedtypes:
        :param fromdate:
        :param todate:
        :return:
        """
        data = dict(Action='CancelFeedSubmissions',
                    SubmittedFromDate=fromdate,
                    SubmittedToDate=todate)
        data.update(self.enumerate_list('FeedSubmissionIdList.Id.', feedids))
        data.update(self.enumerate_list('FeedTypeList.Type.', feedtypes))
        return self.make_request(data)

    def get_feed_submission_result(self, feedid):
        """

        :param feedid:
        :return:
        """
        data = dict(Action='GetFeedSubmissionResult', FeedSubmissionId=feedid)
        return self.make_request(data)


class Reports(MWS):
    """ #Amazon MWS Reports API# """

    ACCOUNT_TYPE = "Merchant"

    ## REPORTS ###

    def get_report(self, report_id):
        """

        :param report_id:
        :return:
        """
        data = dict(Action='GetReport', ReportId=report_id)
        return self.make_request(data)

    def get_report_count(self, report_types=(), acknowledged=None, fromdate=None, todate=None):
        """

        :param report_types:
        :param acknowledged:
        :param fromdate:
        :param todate:
        :return:
        """
        data = dict(Action='GetReportCount',
                    Acknowledged=acknowledged,
                    AvailableFromDate=fromdate,
                    AvailableToDate=todate)
        data.update(self.enumerate_list('ReportTypeList.Type.', report_types))
        return self.make_request(data)

    def get_report_list(self, requestids=(), max_count=None, types=(), acknowledged=None,
                        fromdate=None, todate=None):
        """

        :param requestids:
        :param max_count:
        :param types:
        :param acknowledged:
        :param fromdate:
        :param todate:
        :return:
        """
        data = dict(Action='GetReportList',
                    Acknowledged=acknowledged,
                    AvailableFromDate=fromdate,
                    AvailableToDate=todate,
                    MaxCount=max_count)
        data.update(self.enumerate_list('ReportRequestIdList.Id.', requestids))
        data.update(self.enumerate_list('ReportTypeList.Type.', types))
        return self.make_request(data)

    def get_report_list_by_next_token(self, token):
        """

        :param token:
        :return:
        """
        data = dict(Action='GetReportListByNextToken', NextToken=token)
        return self.make_request(data)

    def get_report_request_count(self, report_types=(), processingstatuses=(), fromdate=None, todate=None):
        """

        :param report_types:
        :param processingstatuses:
        :param fromdate:
        :param todate:
        :return:
        """
        data = dict(Action='GetReportRequestCount',
                    RequestedFromDate=fromdate,
                    RequestedToDate=todate)
        data.update(self.enumerate_list('ReportTypeList.Type.', report_types))
        data.update(self.enumerate_list('ReportProcessingStatusList.Status.', processingstatuses))
        return self.make_request(data)

    def get_report_request_list(self, requestids=(), types=(), processingstatuses=(),
                                max_count=None, fromdate=None, todate=None):
        """

        :param requestids:
        :param types:
        :param processingstatuses:
        :param max_count:
        :param fromdate:
        :param todate:
        :return:
        """
        data = dict(Action='GetReportRequestList',
                    MaxCount=max_count,
                    RequestedFromDate=fromdate,
                    RequestedToDate=todate)
        data.update(self.enumerate_list('ReportRequestIdList.Id.', requestids))
        data.update(self.enumerate_list('ReportTypeList.Type.', types))
        data.update(self.enumerate_list('ReportProcessingStatusList.Status.', processingstatuses))
        return self.make_request(data)

    def get_report_request_list_by_next_token(self, token):
        """

        :param token:
        :return:
        """
        data = dict(Action='GetReportRequestListByNextToken', NextToken=token)
        return self.make_request(data)

    def request_report(self, report_type, start_date=None, end_date=None, marketplaceids=()):
        """

        :param report_type:
        :param start_date:
        :param end_date:
        :param marketplaceids:
        :return:
        """
        data = dict(Action='RequestReport',
                    ReportType=report_type,
                    StartDate=start_date,
                    EndDate=end_date)
        data.update(self.enumerate_list('MarketplaceIdList.Id.', marketplaceids))
        return self.make_request(data)

    """
    ### ReportSchedule ###
    """

    def get_report_schedule_list(self, types=()):
        """

        :param types:
        :return:
        """
        data = dict(Action='GetReportScheduleList')
        data.update(self.enumerate_list('ReportTypeList.Type.', types))
        return self.make_request(data)

    def get_report_schedule_count(self, types=()):
        """

        :param types:
        :return:
        """
        data = dict(Action='GetReportScheduleCount')
        data.update(self.enumerate_list('ReportTypeList.Type.', types))
        return self.make_request(data)


"""
### Orders ###
"""


class Orders(MWS):
    """ Amazon Orders API """

    URI = "/Orders/2013-09-01"
    VERSION = "2013-09-01"
    NS = '{https://mws.amazonservices.com/Orders/2013-09-01}'

    def list_orders(self, marketplaceids, created_after=None, created_before=None, lastupdatedafter=None,
                    lastupdatedbefore=None, orderstatus=(), fulfillment_channels=(),
                    payment_methods=(), buyer_email=None, seller_orderid=None, max_results='100'):
        """

        :param marketplaceids:
        :param created_after:
        :param created_before:
        :param lastupdatedafter:
        :param lastupdatedbefore:
        :param orderstatus:
        :param fulfillment_channels:
        :param payment_methods:
        :param buyer_email:
        :param seller_orderid:
        :param max_results:
        :return:
        """

        data = dict(Action='ListOrders',
                    CreatedAfter=created_after,
                    CreatedBefore=created_before,
                    LastUpdatedAfter=lastupdatedafter,
                    LastUpdatedBefore=lastupdatedbefore,
                    BuyerEmail=buyer_email,
                    SellerOrderId=seller_orderid,
                    MaxResultsPerPage=max_results,
                    )
        data.update(self.enumerate_list('OrderStatus.Status.', orderstatus))
        data.update(self.enumerate_list('MarketplaceId.Id.', marketplaceids))
        data.update(self.enumerate_list('FulfillmentChannel.Channel.', fulfillment_channels))
        data.update(self.enumerate_list('PaymentMethod.Method.', payment_methods))
        return self.make_request(data)

    def list_orders_by_next_token(self, token):
        """

        :param token:
        :return:
        """
        data = dict(Action='ListOrdersByNextToken', NextToken=token)
        return self.make_request(data)

    def get_order(self, amazon_order_ids):
        """

        :param amazon_order_ids:
        :return:
        """
        data = dict(Action='GetOrder')
        data.update(self.enumerate_list('AmazonOrderId.Id.', amazon_order_ids))
        return self.make_request(data)

    def list_order_items(self, amazon_order_id):
        """

        :param amazon_order_id:
        :return:
        """
        data = dict(Action='ListOrderItems', AmazonOrderId=amazon_order_id)
        return self.make_request(data)

    def list_order_items_by_next_token(self, token):
        """

        :param token:
        :return:
        """
        data = dict(Action='ListOrderItemsByNextToken', NextToken=token)
        return self.make_request(data)


class Products(MWS):
    """ Amazon MWS Products API """

    URI = '/Products/2011-10-01'
    VERSION = '2011-10-01'
    NS = '{http://mws.amazonservices.com/schema/Products/2011-10-01}'

    def list_matching_products(self, marketplaceid, query, contextid=None):
        """
        Returns a list of products and their attributes, ordered by
        relevancy, based on a search query that you specify.
        Your search query can be a phrase that describes the product
        or it can be a product identifier such as a UPC, EAN, ISBN, or JAN.

        :param marketplaceid:
        :param query:
        :param contextid:
        :return:
        """
        data = dict(Action='ListMatchingProducts',
                    MarketplaceId=marketplaceid,
                    Query=query,
                    QueryContextId=contextid)
        return self.make_request(data)

    def get_matching_product(self, marketplaceid, asins):
        """
        Returns a list of products and their attributes, based on a list of
        ASIN values that you specify.

        :param marketplaceid:
        :param asins:
        :return:
        """
        data = dict(Action='GetMatchingProduct', MarketplaceId=marketplaceid)
        data.update(self.enumerate_list('ASINList.ASIN.', asins))
        return self.make_request(data)

    def get_matching_product_for_id(self, marketplaceid, type, ids):
        """
        Returns a list of products and their attributes, based on a list of
        product identifier values (ASIN, SellerSKU, UPC, EAN, ISBN, GCID  and JAN)
        The identifier type is case sensitive.
        Added in Fourth Release, API version 2011-10-01

        :param marketplaceid:
        :param type:
        :param ids:
        :return:
        """
        data = dict(Action='GetMatchingProductForId',
                    MarketplaceId=marketplaceid,
                    IdType=type)
        data.update(self.enumerate_list('IdList.Id.', ids))
        return self.make_request(data)

    def get_competitive_pricing_for_sku(self, marketplaceid, skus):
        """
        Returns the current competitive pricing of a product,
        based on the SellerSKU and MarketplaceId that you specify.

        :param marketplaceid:
        :param skus:
        :return:
        """
        data = dict(Action='GetCompetitivePricingForSKU', MarketplaceId=marketplaceid)
        data.update(self.enumerate_list('SellerSKUList.SellerSKU.', skus))
        return self.make_request(data)

    def get_competitive_pricing_for_asin(self, marketplaceid, asins):
        """
        Returns the current competitive pricing of a product,
        based on the ASIN and MarketplaceId that you specify.

        :param marketplaceid:
        :param asins:
        :return:
        """
        data = dict(Action='GetCompetitivePricingForASIN', MarketplaceId=marketplaceid)
        data.update(self.enumerate_list('ASINList.ASIN.', asins))
        return self.make_request(data)

    def get_lowest_offer_listings_for_sku(self, marketplaceid, skus, condition="Any", excludeme="False"):
        """

        :param marketplaceid:
        :param skus:
        :param condition:
        :param excludeme:
        :return:
        """
        data = dict(Action='GetLowestOfferListingsForSKU',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        data.update(self.enumerate_list('SellerSKUList.SellerSKU.', skus))
        return self.make_request(data)

    def get_lowest_offer_listings_for_asin(self, marketplaceid, asins, condition="Any", excludeme="False"):
        """

        :param marketplaceid:
        :param asins:
        :param condition:
        :param excludeme:
        :return:
        """
        data = dict(Action='GetLowestOfferListingsForASIN',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        data.update(self.enumerate_list('ASINList.ASIN.', asins))
        return self.make_request(data)

    def get_lowest_priced_offers_for_sku(self, marketplaceid, sku, condition="New", excludeme="False"):
        """

        :param marketplaceid:
        :param sku:
        :param condition:
        :param excludeme:
        :return:
        """
        data = dict(Action='GetLowestPricedOffersForSKU',
                    MarketplaceId=marketplaceid,
                    SellerSKU=sku,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        return self.make_request(data)

    def get_lowest_priced_offers_for_asin(self, marketplaceid, asin, condition="New", excludeme="False"):
        """

        :param marketplaceid:
        :param asin:
        :param condition:
        :param excludeme:
        :return:
        """
        data = dict(Action='GetLowestPricedOffersForASIN',
                    MarketplaceId=marketplaceid,
                    ASIN=asin,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        return self.make_request(data)

    def get_product_categories_for_sku(self, marketplaceid, sku):
        """

        :param marketplaceid:
        :param sku:
        :return:
        """
        data = dict(Action='GetProductCategoriesForSKU',
                    MarketplaceId=marketplaceid,
                    SellerSKU=sku)
        return self.make_request(data)

    def get_product_categories_for_asin(self, marketplaceid, asin):
        """

        :param marketplaceid:
        :param asin:
        :return:
        """
        data = dict(Action='GetProductCategoriesForASIN',
                    MarketplaceId=marketplaceid,
                    ASIN=asin)
        return self.make_request(data)

    def get_my_price_for_sku(self, marketplaceid, skus, condition=None):
        """

        :param marketplaceid:
        :param skus:
        :param condition:
        :return:
        """
        data = dict(Action='GetMyPriceForSKU',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition)
        data.update(self.enumerate_list('SellerSKUList.SellerSKU.', skus))
        return self.make_request(data)

    def get_my_price_for_asin(self, marketplaceid, asins, condition=None):
        """

        :param marketplaceid:
        :param asins:
        :param condition:
        :return:
        """
        data = dict(Action='GetMyPriceForASIN',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition)
        data.update(self.enumerate_list('ASINList.ASIN.', asins))
        return self.make_request(data)


class Sellers(MWS):
    """ Amazon MWS Sellers API """

    URI = '/Sellers/2011-07-01'
    VERSION = '2011-07-01'
    NS = '{http://mws.amazonservices.com/schema/Sellers/2011-07-01}'

    def list_marketplace_participations(self):
        """
        Returns a list of marketplaces a seller can participate in and
        a list of participations that include seller-specific information in that marketplace.
        The operation returns only those marketplaces where the seller's account is in an active state.

        :return:
        """

        data = dict(Action='ListMarketplaceParticipations')
        return self.make_request(data)

    def list_marketplace_participations_by_next_token(self, token):
        """
        Takes a "NextToken" and returns the same information as "list_marketplace_participations".
        Based on the "NextToken".

        :param token:
        :return:
        """
        data = dict(Action='ListMarketplaceParticipations', NextToken=token)
        return self.make_request(data)


"""
#### Fulfillment APIs ####
"""


class InboundShipments(MWS):
    URI = "/FulfillmentInboundShipment/2010-10-01"
    VERSION = '2010-10-01'

    def list_inbound_shipment_items(self, shipment_id=None, last_updated_after=None, last_updated_before=None):
        """
        Returns a list of items contained in an inbound shipment that you specify with a ShipmentId.
        Alternatively, if you submit the LastUpdatedAfter and LastUpdatedBefore request parameters,
        the ListInboundShipmentItems operation returns inbound shipment items based on when the items
        were last updated. Note that if you specify the ShipmentId, then the LastUpdatedAfter and
        LastUpdatedBefore request parameters are ignored.

        :param shipment_id: int
        :param last_updated_after: date
        :param last_updated_before: date
        :return: a list of items contained in an inbound shipment
        """
        data = dict(Action='ListInboundShipmentItems',
                    ShipmentId=shipment_id,
                    LastUpdatedAfter=last_updated_after,
                    LastUpdatedBefore=last_updated_before)
        return self.make_request(data)

    def list_inbound_shipment_items_by_next_token(self, token):
        """
        Takes a "NextToken" and returns the same information as :func "list_inbound_shipment_items".
        Based on the "NextToken".

        :param token: A string token returned in the response of your previous request to either ListInboundShipmentItems or ListInboundShipmentItemsByNextToken.
        :return: a list of items contained in an inbound shipment
        """
        data = dict(Action='ListInboundShipmentItemsByNextToken',
                    NextToken=token)
        return self.make_request(data)

    def inbound_guidance_for_sku(self, sku_inbound_guidance_list, marketplace_id):
        """
        The GetInboundGuidanceForSKU operation lets a seller know if Amazon recommends sending an item to a given
        marketplace. In some cases, Amazon provides guidance for why a given Seller SKU is not recommended for
        shipment to Amazon's fulfillment network.

        :param sku_inbound_guidance_list:
        :param marketplace_id:
        :return: Dictionary of inbound guidance and reason
        """
        data = dict(Action='GetInboundGuidanceForSKU',
                    MarketplaceId=marketplace_id)

        data.update(self.enumerate_list('SellerSKUList.Id.', sku_inbound_guidance_list))
        return self.make_request(data)

    def inbound_guidance_for_asin(self, asin_inbound_guidance_list, marketplace_id):
        """
        The GetInboundGuidanceForASIN operation lets a seller know if Amazon recommends sending a product to a
        given marketplace. In some cases, Amazon provides guidance for why a given ASIN is not recommended for
        shipment to Amazon's fulfillment network.

        :param asin_list:
        :param marketplace_id:
        :return: Dictionary of inbound guidance and reason
        """
        data = dict(Action='GetInboundGuidanceForASIN',
                    MarketplaceId=marketplace_id)

        data.update(self.enumerate_list('ASINList.Id.', asin_inbound_guidance_list))
        return self.make_request(data)

    def create_inbound_shipment_plan(self,
                                     ship_from_address,
                                     inbound_shipment_plan_request_items,
                                     ship_to_country_code=None,
                                     ship_to_country_ship_to_country_subdivision_code=None,
                                     label_prep_preference=None):
        """
        The CreateInboundShipmentPlan operation returns one or more inbound shipment plans, which provide the
        information you need to create one or more inbound shipments for a set of items that you specify.
        Multiple inbound shipment plans might be required so that items can be optimally placed in Amazon's
        fulfillment network—for example, positioning inventory closer to the customer. Alternatively, two inbound
        shipment plans might be created with the same Amazon fulfillment center destination if the two shipment plans
        require different processing—for example, items that require labels must be shipped separately from
        stickerless, commingled inventory.

        :param ship_from_address:
        :param ship_to_country_code:
        :param ship_to_country_ship_to_country_subdivision_code:
        :param label_prep_preference:
        :param inbound_shipment_plan_request_items:
        :return:
        """
        data = dict(Action='CreateInboundShipmentPlan',
                    ShipFromAddress=ship_from_address,
                    ShipToCountryCode=ship_to_country_code,
                    ShipToCountrySubdivisionCode=ship_to_country_ship_to_country_subdivision_code,
                    LabelPrepPreference=label_prep_preference
                    )
        data.update(self.enumerate_list('InboundShipmentPlanRequestItems.member.',
                                        inbound_shipment_plan_request_items))

        return self.make_request(data)

    def create_inbound_shipment(self, shipment_id, inbound_shipment_header, inbound_shipment_items):
        """

        :param shipment_id:
        :param inbound_shipment_header:
        :param inbound_shipment_items:
        :return:
        """
        data = dict(Action='CreateInboundShipment',
                    ShipmentId=shipment_id)
        data.update(self.enumerate_dict('InboundShipmentHeader', inbound_shipment_header))
        data.update(self.enumerate_dict('InboundShipmentItems', inbound_shipment_items))
        return self.make_request(data)


class Inventory(MWS):
    """ Amazon MWS Inventory Fulfillment API """

    URI = '/FulfillmentInventory/2010-10-01'
    VERSION = '2010-10-01'
    NS = "{http://mws.amazonaws.com/FulfillmentInventory/2010-10-01}"

    def list_inventory_supply(self, skus=(), datetime=None, response_group='Basic'):
        """
        Returns information on available inventory

        :param skus:
        :param datetime:
        :param response_group:
        :return:
        """
        """ """

        data = dict(Action='ListInventorySupply',
                    QueryStartDateTime=datetime,
                    ResponseGroup=response_group,
                    )
        data.update(self.enumerate_list('SellerSkus.member.', skus))
        return self.make_request(data, "POST")

    def list_inventory_supply_by_next_token(self, token):
        """

        :param token:
        :return:
        """
        data = dict(Action='ListInventorySupplyByNextToken', NextToken=token)
        return self.make_request(data, "POST")


class OutboundShipments(MWS):
    URI = "/FulfillmentOutboundShipment/2010-10-01"
    VERSION = "2010-10-01"

    # To be completed


class Recommendations(MWS):

    """ Amazon MWS Recommendations API """

    URI = '/Recommendations/2013-04-01'
    VERSION = '2013-04-01'
    NS = "{https://mws.amazonservices.com/Recommendations/2013-04-01}"

    def get_last_updated_time_for_recommendations(self, marketplaceid):
        """
        Checks whether there are active recommendations for each category for the given marketplace, and if there are,
        returns the time when recommendations were last updated for each category.

        :param marketplaceid:
        :return:
        """

        data = dict(Action='GetLastUpdatedTimeForRecommendations',
                    MarketplaceId=marketplaceid)
        return self.make_request(data, "POST")

    def list_recommendations(self, marketplaceid, recommendationcategory=None):
        """
        Returns your active recommendations for a specific category or for all categories for a specific marketplace.

        :param marketplaceid:
        :param recommendationcategory:
        :return:
        """

        data = dict(Action="ListRecommendations",
                    MarketplaceId=marketplaceid,
                    RecommendationCategory=recommendationcategory)
        return self.make_request(data, "POST")

    def list_recommendations_by_next_token(self, token):
        """
        Returns the next page of recommendations using the NextToken parameter.

        :param token:
        :return:
        """
        data = dict(Action="ListRecommendationsByNextToken",
                    NextToken=token)
        return self.make_request(data, "POST")
