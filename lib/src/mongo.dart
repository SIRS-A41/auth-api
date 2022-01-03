import 'utils.dart';
import 'package:mongo_dart/mongo_dart.dart';

typedef MongoFunction = Function(Db db);

class Mongo {
  late Db test;
  late Db db;
  late DbCollection store;
  late String mongoUrl;

  Mongo(this.mongoUrl)
      : test = Db('$mongoUrl/test'),
        db = Db('$mongoUrl/db');

  Future<void> init() async {
    await test.open();
    await db.open();
    print('Connected to database: $mongoUrl');
    store = test.collection('users');
  }

  Future<bool> hasUser(String email) async {
    final user = await store.findOne(where.eq('email', email));
    return user != null;
  }

  Future<void> newUser(String email, String password) async {
    final salt = generateSalt();
    final hashedPassword = hashPassword(password, salt);
    await store.insertOne({
      'email': email,
      'password': hashedPassword,
      'salt': salt,
    });
  }

  Future<String?> login(String email, String password) async {
    final user = await store.findOne(where.eq('email', email));
    if (user == null) return null;

    final hashedPassword = hashPassword(password, user['salt']);

    if (hashedPassword != user['password']) {
      return null;
    }
    final userId = (user['_id'] as ObjectId).$oid;
    return userId;
  }

  Future<Map<String, dynamic>?> getUser(ObjectId userId) async =>
      await store.findOne(where.eq('_id', userId));

  Future<Map<String, dynamic>?> insert(
      String path, Map<String, dynamic> data) async {
    if (path.endsWith('/')) {
      path = path.substring(0, path.length - 1);
    }
    await db.collection(path).insertOne(data);
    return data;
  }

  Future<Map<String, dynamic>?> write(String path, Map<String, dynamic> data,
      {bool merge = true}) async {
    var pathAux = path.split('/');
    final collection = pathAux.first;
    final documentId = ObjectId.fromHexString(pathAux.last);
    if (merge) {
      var doc = await db
              .collection(collection)
              .findOne(where.eq('_id', documentId)) ??
          {};
      doc.addAll(data);
      await db
          .collection(collection)
          .replaceOne(where.eq('_id', documentId), doc);
      return doc;
    } else {
      await db
          .collection(collection)
          .replaceOne(where.eq('_id', documentId), data);
      return data..addAll({'_id': documentId});
    }
  }

  Future<Map<String, dynamic>?> readDocument(String path) async {
    var pathAux = path.split('/');
    final collection = pathAux.first;
    final documentId = ObjectId.fromHexString(pathAux.last);
    return await db.collection(collection).findOne(where.eq('_id', documentId));
  }

  Future<bool> deleteDocument(String path) async {
    var pathAux = path.split('/');
    final collection = pathAux.first;
    final documentId = ObjectId.fromHexString(pathAux.last);
    final result =
        await db.collection(collection).deleteOne(where.eq('_id', documentId));
    return result.isSuccess;
  }

  Future<List<Map<String, dynamic>>?> readCollection(
    String path, {
    String? field,
    String? operator,
    dynamic? value,
    String? orderBy,
    bool descending = false,
    int? limit,
  }) async {
    if (path.endsWith('/')) {
      path = path.substring(0, path.length - 1);
    }
    final collection = db.collection(path);
    var query = where;
    if (field != null && operator != null && value != null) {
      if (operator == '==') {
        query = query.eq(field, value);
      } else if (operator == '>') {
        query = query.gt(field, value);
      } else if (operator == '<') {
        query = query.lt(field, value);
      } else if (operator == '>=') {
        query = query.gte(field, value);
      } else if (operator == '<=') {
        query = query.lte(field, value);
      }
    }
    if (orderBy != null) {
      query = query.sortBy(orderBy, descending: descending);
    }
    if (limit != null) {
      query.limit(limit);
    }
    return await collection.find(query).toList();
  }

  Future<List<String>?> listCollection(
    String path, {
    String? field,
    String? operator,
    dynamic? value,
    String? orderBy,
    bool descending = false,
    int? limit,
  }) async {
    final documents = await readCollection(
      path,
      field: field,
      operator: operator,
      value: value,
      orderBy: orderBy,
      descending: descending,
      limit: limit,
    );
    if (documents == null || documents.isEmpty) {
      return null;
    }
    return List<String>.from(documents.map(
        (Map<String, dynamic> document) => (document['_id'] as ObjectId).$oid));
  }

  Future<List<String?>> listCollections() async {
    return await db.getCollectionNames();
  }
}
