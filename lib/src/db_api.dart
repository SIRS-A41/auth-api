import 'dart:convert';

import '../server.dart';
import 'mongo.dart';

import 'utils.dart';

import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';

final RegExp regexDocumentPath = RegExp(r'^[a-zA-Z0-9_-]+\/[a-z0-9]+$');
final RegExp regexCollectionPath = RegExp(r'^[a-zA-Z0-9_-]+\/?$');

class DbApi {
  DbApi({required this.mongo});

  final Mongo mongo;

  Handler get router {
    final router = Router();

    // WRITE
    router.post('/<path|.*>', (Request req, String path) async {
      final jsonData = await req.readAsString();
      if (jsonData.isEmpty) {
        return Response(HttpStatus.badRequest, body: 'Provide data to write.');
      }

      try {
        final data = json.decode(jsonData);
        var dataWritten;

        if (regexDocumentPath.hasMatch(path)) {
          final merge = (req.headers['merge'] == 'true');
          // DELETE
          if (data.isEmpty && !merge) {
            if (await mongo.deleteDocument(path)) {
              return Response.ok('Document deleted.');
            } else {
              return Response.internalServerError(
                  body: 'Something went wrong. Try again.');
            }
          } else {
            dataWritten = await mongo.write(path, data, merge: merge);
          }
        } else if (regexCollectionPath.hasMatch(path)) {
          dataWritten = await mongo.insert(path, data);
        } else {
          return Response(HttpStatus.badRequest, body: 'Invalid path format.');
        }
        return Response.ok(
          json.encode(dataWritten),
          headers: {
            HttpHeaders.contentTypeHeader: ContentType.json.mimeType,
          },
        );
      } on FormatException {
        return Response(HttpStatus.badRequest,
            body: 'Data is not a valid JSON.');
      } catch (e) {
        return Response.internalServerError();
      }
    });

    // READ
    router.get('/<path|.*>', (Request req, String path) async {
      var data;
      if (regexDocumentPath.hasMatch(path)) {
        try {
          data = await mongo.readDocument(path);
        } on ArgumentError {
          return Response(HttpStatus.badRequest, body: 'Invalid objectId.');
        }
      } else if (regexCollectionPath.hasMatch(path)) {
        final where = req.headers['where'];
        final operator = req.headers['operator'];
        final value = parseValue(req.headers['value']);
        if (!((where == null && operator == null && value == null) ||
            (where != null && operator != null && value != null))) {
          return Response(HttpStatus.badRequest,
              body: 'Invalid filter parameters.');
        }
        if (operator != null) {
          if (!['==', '<', '>', '<=', '>=', '!='].contains(operator)) {
            return Response(HttpStatus.badRequest,
                body: 'Invalid filter operator.');
          }
        }

        final orderBy = req.headers['orderBy'];
        final descending = req.headers['descending'];
        if (descending != null &&
            descending != 'true' &&
            descending != 'false') {
          return Response(HttpStatus.badRequest,
              body: 'Invalid descending value. Must be "true" or "false".');
        }

        final limit = int.tryParse(req.headers['limit'] ?? '');
        if (limit != null && !(limit is int)) {
          return Response(HttpStatus.badRequest, body: 'Invalid limit number.');
        }

        data = await mongo.readCollection(
          path,
          field: where,
          operator: operator,
          value: value,
          orderBy: orderBy,
          descending: descending == 'true',
          limit: limit,
        );
      } else if (path == '') {
        data = await mongo.listCollections();
      } else {
        return Response(HttpStatus.badRequest, body: 'Invalid path format.');
      }

      return Response.ok(
        jsonEncode(data),
        headers: {
          HttpHeaders.contentTypeHeader: ContentType.json.mimeType,
        },
      );
    });

    final handler = Pipeline()
        .addMiddleware(checkAuthorization())
        .addMiddleware(logDbRequests())
        .addHandler(router);

    return handler;
  }
}
