// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT.

package dynamodb

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/client/metadata"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/private/protocol/jsonrpc"
	"github.com/aws/aws-sdk-go/private/signer/v4"
)

// This is the Amazon DynamoDB API Reference. This guide provides descriptions
// of the low-level DynamoDB API.
//
// This guide is intended for use with the following DynamoDB documentation:
//
//    Amazon DynamoDB Getting Started Guide (http://docs.aws.amazon.com/amazondynamodb/latest/gettingstartedguide/)
// - provides hands-on exercises that help you learn the basics of working with
// DynamoDB. If you are new to DynamoDB, we recommend that you begin with the
// Getting Started Guide.
//
//    Amazon DynamoDB Developer Guide (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/)
// - contains detailed information about DynamoDB concepts, usage, and best
// practices.
//
//    Amazon DynamoDB Streams API Reference (http://docs.aws.amazon.com/dynamodbstreams/latest/APIReference/)
// - provides descriptions and samples of the DynamoDB Streams API. (For more
// information, see Capturing Table Activity with DynamoDB Streams (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html)
// in the Amazon DynamoDB Developer Guide.)
//
//   Instead of making the requests to the low-level DynamoDB API directly
// from your application, we recommend that you use the AWS Software Development
// Kits (SDKs). The easy-to-use libraries in the AWS SDKs make it unnecessary
// to call the low-level DynamoDB API directly from your application. The libraries
// take care of request authentication, serialization, and connection management.
// For more information, see Using the AWS SDKs with DynamoDB (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/UsingAWSSDK.html)
// in the Amazon DynamoDB Developer Guide.
//
// If you decide to code against the low-level DynamoDB API directly, you will
// need to write the necessary code to authenticate your requests. For more
// information on signing your requests, see Using the DynamoDB API (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/API.html)
// in the Amazon DynamoDB Developer Guide.
//
// The following are short descriptions of each low-level API action, organized
// by function.
//
//  Managing Tables
//
//    CreateTable - Creates a table with user-specified provisioned throughput
// settings. You must define a primary key for the table - either a simple primary
// key (partition key), or a composite primary key (partition key and sort key).
// Optionally, you can create one or more secondary indexes, which provide fast
// data access using non-key attributes.
//
//    DescribeTable - Returns metadata for a table, such as table size, status,
// and index information.
//
//    UpdateTable - Modifies the provisioned throughput settings for a table.
// Optionally, you can modify the provisioned throughput settings for global
// secondary indexes on the table.
//
//    ListTables - Returns a list of all tables associated with the current
// AWS account and endpoint.
//
//    DeleteTable - Deletes a table and all of its indexes.
//
//   For conceptual information about managing tables, see Working with Tables
// (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.html)
// in the Amazon DynamoDB Developer Guide.
//
//  Reading Data
//
//    GetItem - Returns a set of attributes for the item that has a given primary
// key. By default, GetItem performs an eventually consistent read; however,
// applications can request a strongly consistent read instead.
//
//    BatchGetItem - Performs multiple GetItem requests for data items using
// their primary keys, from one table or multiple tables. The response from
// BatchGetItem has a size limit of 16 MB and returns a maximum of 100 items.
// Both eventually consistent and strongly consistent reads can be used.
//
//    Query - Returns one or more items from a table or a secondary index.
// You must provide a specific value for the partition key. You can narrow the
// scope of the query using comparison operators against a sort key value, or
// on the index key. Query supports either eventual or strong consistency. A
// single response has a size limit of 1 MB.
//
//    Scan - Reads every item in a table; the result set is eventually consistent.
// You can limit the number of items returned by filtering the data attributes,
// using conditional expressions. Scan can be used to enable ad-hoc querying
// of a table against non-key attributes; however, since this is a full table
// scan without using an index, Scan should not be used for any application
// query use case that requires predictable performance.
//
//   For conceptual information about reading data, see Working with Items
// (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html)
// and Query and Scan Operations (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/QueryAndScan.html)
// in the Amazon DynamoDB Developer Guide.
//
//  Modifying Data
//
//    PutItem - Creates a new item, or replaces an existing item with a new
// item (including all the attributes). By default, if an item in the table
// already exists with the same primary key, the new item completely replaces
// the existing item. You can use conditional operators to replace an item only
// if its attribute values match certain conditions, or to insert a new item
// only if that item doesn't already exist.
//
//    UpdateItem - Modifies the attributes of an existing item. You can also
// use conditional operators to perform an update only if the item's attribute
// values match certain conditions.
//
//    DeleteItem - Deletes an item in a table by primary key. You can use conditional
// operators to perform a delete an item only if the item's attribute values
// match certain conditions.
//
//    BatchWriteItem - Performs multiple PutItem and DeleteItem requests across
// multiple tables in a single request. A failure of any request(s) in the batch
// will not cause the entire BatchWriteItem operation to fail. Supports batches
// of up to 25 items to put or delete, with a maximum total request size of
// 16 MB.
//
//   For conceptual information about modifying data, see Working with Items
// (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html)
// and Query and Scan Operations (http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/QueryAndScan.html)
// in the Amazon DynamoDB Developer Guide.
//The service client's operations are safe to be used concurrently.
// It is not safe to mutate any of the client's properties though.
type DynamoDB struct {
	*client.Client
}

// Used for custom client initialization logic
var initClient func(*client.Client)

// Used for custom request initialization logic
var initRequest func(*request.Request)

// A ServiceName is the name of the service the client will make API calls to.
const ServiceName = "dynamodb"

// New creates a new instance of the DynamoDB client with a session.
// If additional configuration is needed for the client instance use the optional
// aws.Config parameter to add your extra config.
//
// Example:
//     // Create a DynamoDB client from just a session.
//     svc := dynamodb.New(mySession)
//
//     // Create a DynamoDB client with additional configuration
//     svc := dynamodb.New(mySession, aws.NewConfig().WithRegion("us-west-2"))
func New(p client.ConfigProvider, cfgs ...*aws.Config) *DynamoDB {
	c := p.ClientConfig(ServiceName, cfgs...)
	return newClient(*c.Config, c.Handlers, c.Endpoint, c.SigningRegion)
}

// newClient creates, initializes and returns a new service client instance.
func newClient(cfg aws.Config, handlers request.Handlers, endpoint, signingRegion string) *DynamoDB {
	svc := &DynamoDB{
		Client: client.New(
			cfg,
			metadata.ClientInfo{
				ServiceName:   ServiceName,
				SigningRegion: signingRegion,
				Endpoint:      endpoint,
				APIVersion:    "2012-08-10",
				JSONVersion:   "1.0",
				TargetPrefix:  "DynamoDB_20120810",
			},
			handlers,
		),
	}

	// Handlers
	svc.Handlers.Sign.PushBack(v4.Sign)
	svc.Handlers.Build.PushBackNamed(jsonrpc.BuildHandler)
	svc.Handlers.Unmarshal.PushBackNamed(jsonrpc.UnmarshalHandler)
	svc.Handlers.UnmarshalMeta.PushBackNamed(jsonrpc.UnmarshalMetaHandler)
	svc.Handlers.UnmarshalError.PushBackNamed(jsonrpc.UnmarshalErrorHandler)

	// Run custom client initialization if present
	if initClient != nil {
		initClient(svc.Client)
	}

	return svc
}

// newRequest creates a new request for a DynamoDB operation and runs any
// custom request initialization.
func (c *DynamoDB) newRequest(op *request.Operation, params, data interface{}) *request.Request {
	req := c.NewRequest(op, params, data)

	// Run custom request initialization if present
	if initRequest != nil {
		initRequest(req)
	}

	return req
}